(function () {
  const SCAN_MESSAGE = "ARGUS_PAGE_SCAN";
  const RESCAN_MESSAGE = "ARGUS_RESCAN_PAGE";
  const PASSWORD_FOCUS_MESSAGE = "ARGUS_PASSWORD_FIELD_FOCUSED";
  const FORM_SUBMITTED_MESSAGE = "ARGUS_FORM_SUBMITTED";
  const DOWNLOAD_CLICKED_MESSAGE = "ARGUS_DOWNLOAD_CLICKED";
  const PAGE_CHANGED_MESSAGE = "ARGUS_PAGE_CHANGED";
  const BADGE_ID = "argus-scan-badge";
  const BADGE_PANEL_ID = "argus-scan-detail-panel";
  let currentPageKey = getPageKey();
  let pageChangeTimer = null;
  let finalScanTimer = null;
  let latestRenderedScan = null;
  let currentNavigationId = null;
  // Map of eventKey -> last-sent timestamp (throttle, not permanent suppression).
  const sentPageEvents = new Map();
  const PASSWORD_FOCUS_THROTTLE_MS = 3000;

  // Domain/category lists come from the shared ArgusSharedLists module (loaded as
  // the first content script — single source of truth with the worker, F8).
  const SHARED = typeof ArgusSharedLists !== "undefined" ? ArgusSharedLists : {};
  const TRUSTED_DOMAINS = SHARED.TRUSTED_DOMAINS || [];
  const SEARCH_ENGINE_DOMAINS = SHARED.SEARCH_ENGINE_DOMAINS || [];
  const KNOWN_IDENTITY_DOMAINS = SHARED.KNOWN_IDENTITY_DOMAINS || [];
  const KNOWN_PAYMENT_DOMAINS = SHARED.KNOWN_PAYMENT_DOMAINS || [];
  const KEYWORDS = SHARED.KEYWORDS || {};
  const SUSPICIOUS_DOMAIN_WORDS = SHARED.SUSPICIOUS_DOMAIN_WORDS || [];
  const MULTI_LABEL_SUFFIXES = new Set(SHARED.MULTI_LABEL_SUFFIXES || []);

  function normalizeText(value) {
    return String(value || "").replace(/\s+/g, " ").trim().toLowerCase();
  }

  function unique(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function truncate(value, length) {
    const text = String(value || "").trim();
    return text.length > length ? `${text.slice(0, length - 1)}...` : text;
  }

  function sanitizeUrl(value) {
    try {
      const parsed = new URL(value, window.location.href);
      return `${parsed.origin}${parsed.pathname}`;
    } catch (error) {
      return "";
    }
  }

  function getUrlMetadata(value) {
    try {
      const parsed = new URL(value, window.location.href);
      return {
        protocol: parsed.protocol,
        hostname: parsed.hostname.toLowerCase(),
        pathname: parsed.pathname || "/",
        sanitizedUrl: `${parsed.origin}${parsed.pathname}`
      };
    } catch (error) {
      return {
        protocol: "",
        hostname: "",
        pathname: "",
        sanitizedUrl: ""
      };
    }
  }

  function isDomainMatch(domain, expectedDomain) {
    return domain === expectedDomain || domain.endsWith(`.${expectedDomain}`);
  }

  function isSameSiteDomain(domain, otherDomain) {
    if (!domain || !otherDomain) {
      return false;
    }

    if (domain === otherDomain || domain.endsWith(`.${otherDomain}`) || otherDomain.endsWith(`.${domain}`)) {
      return true;
    }

    return getSiteDomain(domain) === getSiteDomain(otherDomain);
  }

  function getSiteDomain(domain) {
    const hostname = String(domain || "").toLowerCase().replace(/^\.+|\.+$/g, "");
    if (!hostname || hostname === "localhost" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":")) {
      return hostname;
    }

    const labels = hostname.split(".");
    if (labels.length <= 2) return hostname;
    const suffix = labels.slice(-2).join(".");
    return MULTI_LABEL_SUFFIXES.has(suffix) ? labels.slice(-3).join(".") : suffix;
  }

  function isTrustedDomain(domain) {
    return TRUSTED_DOMAINS.some((trustedDomain) => isDomainMatch(domain, trustedDomain));
  }

  function isKnownIdentityProvider(domain) {
    return KNOWN_IDENTITY_DOMAINS.some((candidate) => isDomainMatch(String(domain || "").toLowerCase(), candidate));
  }

  function isKnownPaymentProvider(domain) {
    return KNOWN_PAYMENT_DOMAINS.some((candidate) => isDomainMatch(String(domain || "").toLowerCase(), candidate));
  }

  function isSearchEnginePage(url, domain, pathname) {
    const searchDomain = SEARCH_ENGINE_DOMAINS.some((candidate) => isDomainMatch(domain, candidate)) || isGoogleDomain(domain);

    if (!searchDomain) {
      return false;
    }

    if (isGoogleDomain(domain) || domain.includes("bing.") || domain === "search.brave.com") {
      return pathname === "/search";
    }

    if (domain.includes("duckduckgo.com")) {
      return pathname === "/" || pathname === "/html" || pathname === "/lite";
    }

    return false;
  }

  function isGoogleDomain(domain) {
    return /^(.+\.)?google\.[a-z.]+$/i.test(domain);
  }

  function getElementText(element) {
    return normalizeText([
      element.innerText,
      element.textContent,
      element.getAttribute("aria-label"),
      element.getAttribute("title")
    ].filter(Boolean).join(" "));
  }

  function getLimitedPageTextSurface() {
    const textElements = Array.from(document.querySelectorAll("h1, h2, h3, p, li, label, button, a, [role='button']"));
    return textElements
      .filter(isVisibleElement)
      .slice(0, 140)
      .map((element) => truncate(getElementText(element), 160))
      .join(" ");
  }

  function getInputSurface(input) {
    return normalizeText([
      input.type,
      input.name,
      input.id,
      input.placeholder,
      input.autocomplete,
      input.getAttribute("aria-label"),
      input.getAttribute("title")
    ].filter(Boolean).join(" "));
  }

  function getSensitiveFieldKind(input) {
    const type = normalizeText(input.type || input.tagName);
    const surface = getInputSurface(input);

    if (type === "password" || /current-password|new-password|password|passwd|passcode/.test(surface)) {
      return "password";
    }
    if (/one-time-code|otp|verification|security code|auth code|device[_\s-]?check|\bpin\b/.test(surface)) {
      return "verification";
    }
    if (/credit|card number|cardnumber|cvc|cvv|payment|bank account|routing|wallet/.test(surface)) {
      return "payment";
    }
    if (/recovery|seed phrase|secret|private key|access phrase|token|vault key/.test(surface)) {
      return "secret";
    }
    return "";
  }

  function getScriptSurface(script) {
    return normalizeText([
      script.src,
      script.textContent
    ].filter(Boolean).join(" ").slice(0, 12000));
  }

  function collectKeywordMatches(surface, keywords) {
    return unique(keywords.filter((keyword) => surface.includes(keyword)));
  }

  function isApkHref(href) {
    if (!href) {
      return false;
    }

    try {
      const parsed = new URL(href, window.location.href);
      return /\.apk$/i.test(parsed.pathname);
    } catch (error) {
      return /\.apk(?:$|[?#])/i.test(href);
    }
  }

  function getAttributeSurface(element) {
    return normalizeText([
      element.id,
      element.className,
      element.name,
      element.href,
      element.src,
      element.currentSrc,
      element.alt,
      element.title,
      element.getAttribute("aria-label")
    ].filter(Boolean).join(" "));
  }

  function isVisibleElement(element) {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);

    return (
      rect.width > 1 &&
      rect.height > 1 &&
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      Number(style.opacity || 1) > 0.05
    );
  }

  function isLargeBannerImage(image) {
    if (!isVisibleElement(image)) {
      return false;
    }

    const rect = image.getBoundingClientRect();
    const ratio = rect.width / Math.max(rect.height, 1);

    return (
      rect.width * rect.height >= 24000 &&
      rect.width >= 220 &&
      rect.height >= 60 &&
      (ratio >= 1.65 || rect.width >= window.innerWidth * 0.35)
    );
  }

  function getAdHeavySignals(images, links, safeSurface) {
    const adHeavySignals = [];
    const largeImages = images.filter(isLargeBannerImage);
    const linkedLargeImages = largeImages.filter((image) => Boolean(image.closest("a[href]")));
    const iframes = Array.from(document.querySelectorAll("iframe"));
    const pageHost = window.location.hostname;
    const externalLinks = links.filter((link) => {
      try {
        const linkHost = new URL(link.href, window.location.href).hostname;
        return linkHost && linkHost !== pageHost;
      } catch (error) {
        return false;
      }
    });

    const candidateElements = Array.from(document.querySelectorAll("[class], [id], iframe, ins"));
    const adLikeElements = candidateElements.filter((element) => (
      /(^|[-_\s])(ad|ads|advert|banner|promo|popup|sponsor|affiliate)([-_\s]|$)/i.test(getAttributeSurface(element))
    ));

    const fixedOrStickyElements = candidateElements.filter((element) => {
      if (!isVisibleElement(element)) {
        return false;
      }

      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);
      const nearViewportEdge = rect.top <= 24 || rect.bottom >= window.innerHeight - 24;

      return (
        (style.position === "fixed" || style.position === "sticky") &&
        rect.width * rect.height >= 12000 &&
        nearViewportEdge
      );
    });

    const foundAdKeywords = collectKeywordMatches(`${safeSurface} ${adLikeElements.map(getAttributeSurface).join(" ")}`, KEYWORDS.ad);

    if (largeImages.length >= 6) {
      adHeavySignals.push(`Many large banner-style images detected (${largeImages.length}).`);
    }

    if (linkedLargeImages.length >= 4) {
      adHeavySignals.push(`Many clickable image banners detected (${linkedLargeImages.length}).`);
    }

    if (adLikeElements.length >= 4) {
      adHeavySignals.push(`Many ad/banner/promo elements detected (${adLikeElements.length}).`);
    }

    if (fixedOrStickyElements.length >= 1 && (largeImages.length >= 4 || adLikeElements.length >= 2)) {
      adHeavySignals.push("Sticky or fixed advertising-style element detected.");
    }

    if (iframes.length >= 3) {
      adHeavySignals.push(`Multiple iframe embeds detected (${iframes.length}).`);
    }

    if (externalLinks.length >= 12 && linkedLargeImages.length >= 3) {
      adHeavySignals.push(`Many external links combined with clickable banners detected (${externalLinks.length}).`);
    }

    if (foundAdKeywords.length >= 3) {
      adHeavySignals.push(`Advertising or promotion language detected: ${foundAdKeywords.slice(0, 6).join(", ")}.`);
    }

    return {
      adHeavySignals,
      foundAdKeywords,
      adLikeElementCount: adLikeElements.length,
      largeImageCount: largeImages.length,
      linkedLargeImageCount: linkedLargeImages.length,
      fixedOrStickyElementCount: fixedOrStickyElements.length,
      iframeCount: iframes.length,
      externalLinkCount: externalLinks.length,
      hasAdHeavySignal: adHeavySignals.length > 0
    };
  }

  function extractDataLeakSignals(forms, links, buttons, iframes, scripts, currentDomain) {
    const formActionUrls = [];
    let emptyFormActionCount = 0;
    let httpFormActionCount = 0;
    let crossDomainFormActionCount = 0;
    let knownIdentityProviderFormCount = 0;
    let passwordCrossDomainForm = false;
    let otpOrPaymentCrossDomainForm = false;
    let passwordHttpForm = false;
    let otpOrPaymentHttpForm = false;
    let sensitiveFormCount = 0;
    let sameOriginSensitiveHttpForm = false;
    let httpPageWithSensitiveForm = false;
    const evasiveBehaviorSignals = extractEvasiveBehaviorSignals(forms, links, buttons, iframes, scripts, currentDomain);

    forms.forEach((form) => {
      const rawAction = (form.getAttribute("action") || "").trim();
      if (!rawAction) {
        emptyFormActionCount += 1;
      }

      const actionMeta = getUrlMetadata(rawAction || window.location.href);
      if (!actionMeta.sanitizedUrl) {
        return;
      }

      formActionUrls.push(actionMeta.sanitizedUrl);

      const isHttpAction = actionMeta.protocol === "http:";
      const isKnownIdentityAction = isKnownIdentityProvider(actionMeta.hostname);
      const isKnownPaymentAction = isKnownPaymentProvider(actionMeta.hostname);
      const isCrossDomainAction = actionMeta.hostname && !isSameSiteDomain(currentDomain, actionMeta.hostname) && !isKnownIdentityAction && !isKnownPaymentAction;
      const formInputs = Array.from(form.querySelectorAll("input, textarea, select"));
      const sensitiveKinds = formInputs.map(getSensitiveFieldKind).filter(Boolean);
      const hasPasswordInForm = sensitiveKinds.includes("password");
      const hasOtpPaymentBankField = sensitiveKinds.some((kind) => kind === "verification" || kind === "payment");
      const hasSensitiveField = sensitiveKinds.length > 0;

      if (hasSensitiveField) {
        sensitiveFormCount += 1;
      }

      if (isHttpAction) {
        httpFormActionCount += 1;
      }

      if (isCrossDomainAction) {
        crossDomainFormActionCount += 1;
        passwordCrossDomainForm = passwordCrossDomainForm || hasPasswordInForm;
        otpOrPaymentCrossDomainForm = otpOrPaymentCrossDomainForm || hasOtpPaymentBankField;
      }
      if (isKnownIdentityAction) knownIdentityProviderFormCount += 1;

      passwordHttpForm = passwordHttpForm || (isHttpAction && hasPasswordInForm);
      otpOrPaymentHttpForm = otpOrPaymentHttpForm || (isHttpAction && hasOtpPaymentBankField);
      sameOriginSensitiveHttpForm = sameOriginSensitiveHttpForm || (isHttpAction && !isCrossDomainAction && hasSensitiveField);
      httpPageWithSensitiveForm = httpPageWithSensitiveForm || (window.location.protocol === "http:" && hasSensitiveField);
    });

    const hiddenInputCount = Array.from(document.querySelectorAll("input[type='hidden'], input[hidden]")).length;
    const hiddenIframeCount = iframes.filter((iframe) => !isVisibleElement(iframe)).length;
    const externalScripts = scripts
      .filter((script) => script.src)
      .map((script) => getUrlMetadata(script.src))
      .filter((meta) => meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname));
    const thirdPartyIframes = iframes
      .filter((iframe) => iframe.src)
      .map((iframe) => getUrlMetadata(iframe.src))
      .filter((meta) => meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname));
    const redirectAwayLinks = links
      .map((link) => getUrlMetadata(link.href))
      .filter((meta) => meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname));
    const thirdPartyApkLinks = links
      .filter((link) => isApkHref(link.href))
      .map((link) => getUrlMetadata(link.href))
      .filter((meta) => meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname))
      .map((meta) => meta.sanitizedUrl)
      .slice(0, 20);
    const httpApkLinks = links
      .filter((link) => isApkHref(link.href))
      .map((link) => getUrlMetadata(link.href))
      .filter((meta) => meta.protocol === "http:")
      .map((meta) => meta.sanitizedUrl)
      .slice(0, 20);
    const fakeDownloadButtons = buttons.filter((button) => /download|install|continue to download|play now|watch now|ดาวน์โหลด|ติดตั้ง/i.test(getElementText(button)));

    return {
      formCount: forms.length,
      sensitiveFormCount,
      formActionUrls: unique(formActionUrls).slice(0, 30),
      emptyFormActionCount,
      httpFormActionCount,
      crossDomainFormActionCount,
      knownIdentityProviderFormCount,
      passwordCrossDomainForm,
      otpOrPaymentCrossDomainForm,
      passwordHttpForm,
      otpOrPaymentHttpForm,
      sameOriginSensitiveHttpForm,
      httpPageWithSensitiveForm,
      hiddenInputCount,
      hiddenIframeCount,
      externalScriptCount: externalScripts.length,
      thirdPartyIframeCount: thirdPartyIframes.length,
      redirectAwayLinkCount: redirectAwayLinks.length,
      thirdPartyApkLinks,
      httpApkLinks,
      fakeDownloadButtonNearEmbed: fakeDownloadButtons.length > 0 && (iframes.length > 0 || externalScripts.length > 0),
      externalScriptDomains: unique(externalScripts.map((meta) => meta.hostname)).slice(0, 20),
      thirdPartyIframeDomains: unique(thirdPartyIframes.map((meta) => meta.hostname)).slice(0, 20),
      redirectAwayDomains: unique(redirectAwayLinks.map((meta) => meta.hostname)).slice(0, 20),
      ...evasiveBehaviorSignals
    };
  }

  function extractEvasiveBehaviorSignals(forms, links, buttons, iframes, scripts, currentDomain) {
    const inputs = Array.from(document.querySelectorAll("input, textarea"));
    const scriptSurfaces = scripts.map(getScriptSurface);
    const combinedScriptSurface = scriptSurfaces.join(" ");
    const inlineScripts = scripts.filter((script) => !script.src && normalizeText(script.textContent).length > 20);
    const externalUrlHints = extractExternalUrlHints(combinedScriptSurface, currentDomain);
    const jsNetworkSinkCount = countPattern(combinedScriptSurface, /\b(fetch|sendbeacon|xmlhttprequest)\b|new\s+image|\.src\s*=|navigator\.sendbeacon/gi);
    const dynamicEndpointAssemblyCount = countPattern(combinedScriptSurface, /fromcharcode|endpointparts|\.join\s*\(|encodeuricomponent|json\.stringify|btoa\s*\(|atob\s*\(|charcodeat|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi);
    const delayedRelayIndicator = /settimeout|requestidlecallback|setinterval/.test(combinedScriptSurface) && jsNetworkSinkCount > 0;
    const popupMessageTrapIndicator = /window\.open|postmessage|window\.opener|addeventlistener\s*\(\s*["']message/.test(combinedScriptSurface);
    const clipboardReadIndicator = /navigator\.clipboard|readtext\s*\(/.test(combinedScriptSurface);
    const fileMetadataHarvestIndicator = /files\s*\)|\.files|file\.name|file\.size|file\.type/.test(combinedScriptSurface) && inputs.some((input) => normalizeText(input.type) === "file");
    const guardedNetworkToggleIndicator = /allownetwork|argus_test_allow_network|typedvaluesincluded|valueincluded|valuesincluded/.test(combinedScriptSurface);
    const formValueReadIndicator = /(?:queryselector|getelementbyid|elements|target|currenttarget)[^;{}]{0,100}\.value\b|\.value\s*[;,)]/i.test(combinedScriptSurface);
    const formDataReadIndicator = /new\s+formdata\s*\(|formdata\s*\(/i.test(combinedScriptSurface);
    const sensitiveStorageWriteIndicator = /(?:localstorage|sessionstorage)\.setitem\s*\([^)]{0,160}(?:password|passwd|otp|token|secret|credential|recovery|seed|private|card|account)/i.test(combinedScriptSurface);
    const cookieReadIndicator = /document\.cookie\b/i.test(combinedScriptSurface);
    const encodedPayloadIndicator = /\b(?:btoa|encodeuricomponent|textencoder|string\.fromcharcode)\s*\(/i.test(combinedScriptSurface);
    const webSocketSendIndicator = /new\s+websocket\s*\(|\.send\s*\([^)]{0,160}(?:value|formdata|password|otp|token|secret)/i.test(combinedScriptSurface);
    const wildcardPostMessageIndicator = /postmessage\s*\([^)]{0,240}["']\*["']/i.test(combinedScriptSurface);
    const preventedSubmitIndicator = /preventdefault\s*\(/.test(combinedScriptSurface) && forms.length > 0;
    const localFormWithJsSinkIndicator = forms.some((form) => {
      const actionMeta = getUrlMetadata(form.getAttribute("action") || "");
      const isLocalAction = !actionMeta.hostname || isSameSiteDomain(currentDomain, actionMeta.hostname);
      return isLocalAction && (preventedSubmitIndicator || jsNetworkSinkCount > 0);
    });
    const credentialLikeTextFieldCount = inputs.filter((input) => {
      const type = normalizeText(input.type || input.tagName);
      const surface = getInputSurface(input);
      return (
        type !== "password" &&
        /password|passcode|passwd|secret|recovery|seed|phrase|access phrase|current-password|one-time-code|otp|token|device[_\s-]?check|verification|code|pin/.test(surface)
      );
    }).length;
    const sensitiveTextareaCount = inputs.filter((input) => {
      const surface = getInputSurface(input);
      return input.tagName === "TEXTAREA" && /recovery|seed|phrase|secret|vault|backup|token|key|note/.test(surface);
    }).length;
    const deceptiveLowFrictionContent = /sync|connect|calendar|vault|recovery|workspace|profile|consent|approve|continue/.test(normalizeText([
      document.title,
      getLimitedPageTextSurface(),
      buttons.map(getElementText).join(" ")
    ].join(" ")));

    return {
      inlineScriptCount: inlineScripts.length,
      scriptNetworkSinkCount: jsNetworkSinkCount,
      dynamicEndpointAssemblyCount,
      externalUrlHints,
      delayedRelayIndicator,
      popupMessageTrapIndicator,
      clipboardReadIndicator,
      fileMetadataHarvestIndicator,
      guardedNetworkToggleIndicator,
      formValueReadIndicator,
      formDataReadIndicator,
      sensitiveStorageWriteIndicator,
      cookieReadIndicator,
      encodedPayloadIndicator,
      webSocketSendIndicator,
      wildcardPostMessageIndicator,
      preventedSubmitIndicator,
      localFormWithJsSinkIndicator,
      credentialLikeTextFieldCount,
      sensitiveTextareaCount,
      deceptiveLowFrictionContent
    };
  }

  function extractSecuritySignals(scripts, iframes, currentDomain) {
    const thirdPartyScriptWithoutIntegrityCount = scripts.filter((script) => {
      if (!script.src || script.integrity) return false;
      const meta = getUrlMetadata(script.src);
      return meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname);
    }).length;
    const unsandboxedThirdPartyIframeCount = iframes.filter((iframe) => {
      if (!iframe.src || iframe.hasAttribute("sandbox")) return false;
      const meta = getUrlMetadata(iframe.src);
      return meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname);
    }).length;
    const metaCsp = Boolean(document.querySelector("meta[http-equiv='Content-Security-Policy' i]"));

    return {
      responseHeadersObserved: false,
      hasContentSecurityPolicy: metaCsp,
      hasStrictTransportSecurity: false,
      hasXContentTypeOptions: false,
      hasReferrerPolicy: Boolean(document.querySelector("meta[name='referrer' i]")),
      hasPermissionsPolicy: false,
      missingSecurityHeaderCount: 0,
      mixedContentRequestCount: 0,
      insecureActiveContentRequestCount: 0,
      thirdPartyScriptWithoutIntegrityCount,
      unsandboxedThirdPartyIframeCount
    };
  }

  function extractExternalUrlHints(surface, currentDomain) {
    const hints = [];
    const directUrlPattern = /https?:\/\/[a-z0-9.-]+(?:\/[a-z0-9._~:/?#[\]@!$&'()*+,;=-]*)?/gi;
    const domainLikePattern = /\b[a-z0-9-]+\.(?:invalid|com|net|org|io|app|site|xyz|top|click|shop|info)\b/gi;
    const matches = `${surface}`.match(directUrlPattern) || [];
    matches.forEach((value) => {
      const meta = getUrlMetadata(value);
      if (meta.hostname && !isSameSiteDomain(currentDomain, meta.hostname)) {
        hints.push(meta.sanitizedUrl);
      }
    });

    const domainMatches = `${surface}`.match(domainLikePattern) || [];
    domainMatches.forEach((value) => {
      const hostname = value.toLowerCase();
      if (hostname && !isSameSiteDomain(currentDomain, hostname)) {
        hints.push(hostname);
      }
    });

    return unique(hints).slice(0, 20);
  }

  function countPattern(value, pattern) {
    const matches = String(value || "").match(pattern);
    return matches ? matches.length : 0;
  }

  function extractUrlLexicalSignals(parsedUrl) {
    const domain = parsedUrl.hostname.toLowerCase();
    const labels = domain.split(".").filter(Boolean);
    const siteLabels = getSiteDomain(domain).split(".").filter(Boolean).length;
    const subdomainCount = Math.max(0, labels.length - siteLabels);
    const digitCount = (domain.match(/\d/g) || []).length;
    const hyphenCount = (domain.match(/-/g) || []).length;
    const encodedCharCount = (parsedUrl.pathname.match(/%[0-9a-f]{2}/gi) || []).length;
    const credentialPathWordCount = (normalizeText(parsedUrl.pathname).match(/login|signin|sign-in|verify|account|auth|secure|wallet|bank/g) || []).length;
    const hasAtSymbol = parsedUrl.href.includes("@");
    const isDomainIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || /^\[[0-9a-f:]+\]$/i.test(domain);
    const hasObfuscation = encodedCharCount >= 2 || hasAtSymbol || domain.startsWith("xn--") || domain.includes(".xn--");
    const domainDigitRatio = digitCount / Math.max(1, domain.length);
    const excessiveSubdomainCount = Math.max(0, subdomainCount - 2);
    const lexicalRiskCount = [
      isDomainIP,
      parsedUrl.href.length >= 100,
      excessiveSubdomainCount >= 2,
      hasObfuscation,
      domainDigitRatio >= 0.25,
      hyphenCount >= 3,
      credentialPathWordCount >= 1
    ].filter(Boolean).length;

    return {
      urlLength: parsedUrl.href.length,
      domainLength: domain.length,
      isDomainIP,
      subdomainCount,
      excessiveSubdomainCount,
      hasObfuscation,
      obfuscatedCharCount: encodedCharCount,
      domainDigitRatio,
      hyphenCount,
      credentialPathWordCount,
      hasAtSymbol,
      lexicalRiskCount
    };
  }

  function scanPage() {
    const parsedUrl = new URL(window.location.href);
    const domain = parsedUrl.hostname.toLowerCase() || "local-file";
    const pathname = parsedUrl.pathname || "/";
    const url = `${parsedUrl.origin}${pathname}`;
    const inputs = Array.from(document.querySelectorAll("input"));
    const links = Array.from(document.querySelectorAll("a[href]"));
    const buttons = Array.from(document.querySelectorAll("button, input[type='button'], input[type='submit'], [role='button']"));
    const images = Array.from(document.querySelectorAll("img"));
    const metas = Array.from(document.querySelectorAll("meta[name], meta[property]"));
    const forms = Array.from(document.querySelectorAll("form"));
    const iframes = Array.from(document.querySelectorAll("iframe"));
    const scripts = Array.from(document.querySelectorAll("script"));

    const buttonTexts = unique(buttons.map((button) => truncate(getElementText(button), 80))).slice(0, 50);
    const anchorHrefs = unique(links.map((link) => sanitizeUrl(link.href))).slice(0, 80);
    const inputSurface = inputs.map(getInputSurface).join(" ");
    const linkSurface = links.map((link) => `${getElementText(link)} ${sanitizeUrl(link.href)}`).join(" ");
    const buttonSurface = buttonTexts.join(" ");
    const imageSurface = images.map((image) => normalizeText([image.alt, image.title, sanitizeUrl(image.currentSrc || image.src)].filter(Boolean).join(" "))).join(" ");
    const metaSurface = metas.map((meta) => normalizeText(meta.content)).join(" ");
    const safeKeywordSurface = normalizeText([
      document.title,
      inputSurface,
      linkSurface,
      buttonSurface,
      imageSurface,
      metaSurface,
      getLimitedPageTextSurface()
    ].join(" "));

    const passwordFields = inputs.filter((input) => normalizeText(input.type) === "password");
    const otpFields = inputs.filter((input) => collectKeywordMatches(getInputSurface(input), KEYWORDS.otp).length > 0);
    const apkLinks = links
      .filter((link) => isApkHref(link.href))
      .map((link) => ({
        text: truncate(getElementText(link) || "(no link text)", 80),
        href: sanitizeUrl(link.href)
      }));

    const suspiciousDomainSignals = SUSPICIOUS_DOMAIN_WORDS
      .filter((word) => domain.includes(word))
      .map((word) => `Domain contains suspicious word: ${word}.`);

    const categoryKeywordSignals = {
      appStore: collectKeywordMatches(safeKeywordSurface, KEYWORDS.appStore),
      gambling: collectKeywordMatches(safeKeywordSurface, KEYWORDS.gambling),
      adult: collectKeywordMatches(safeKeywordSurface, KEYWORDS.adult),
      banking: collectKeywordMatches(safeKeywordSurface, KEYWORDS.banking),
      investment: collectKeywordMatches(safeKeywordSurface, KEYWORDS.investment),
      techSupport: collectKeywordMatches(safeKeywordSurface, KEYWORDS.techSupport),
      popupAbuse: collectKeywordMatches(safeKeywordSurface, KEYWORDS.popupAbuse),
      fakeShopping: collectKeywordMatches(safeKeywordSurface, KEYWORDS.fakeShopping),
      prize: collectKeywordMatches(safeKeywordSurface, KEYWORDS.prize),
      pirated: collectKeywordMatches(safeKeywordSurface, KEYWORDS.pirated)
    };

    return {
      url,
      domain,
      pathname,
      pageProtocol: parsedUrl.protocol,
      urlLexicalSignals: extractUrlLexicalSignals(parsedUrl),
      isSearchEnginePage: isSearchEnginePage(url, domain, pathname),
      isTrustedDomain: isTrustedDomain(domain),
      passwordFieldCount: passwordFields.length,
      hasPasswordField: passwordFields.length > 0,
      hasOTP: collectKeywordMatches(safeKeywordSurface, KEYWORDS.otp).length > 0 || otpFields.length > 0,
      hasLoginKeyword: collectKeywordMatches(safeKeywordSurface, KEYWORDS.login).length > 0,
      inputFieldCount: inputs.length,
      apkLinks,
      buttonTexts,
      anchorHrefs,
      foundStoreKeywords: categoryKeywordSignals.appStore,
      suspiciousDomainSignals,
      foundGamblingKeywords: categoryKeywordSignals.gambling,
      foundAdultKeywords: categoryKeywordSignals.adult,
      foundBankingKeywords: categoryKeywordSignals.banking,
      foundInvestmentKeywords: categoryKeywordSignals.investment,
      foundTechSupportKeywords: categoryKeywordSignals.techSupport,
      foundPopupAbuseKeywords: categoryKeywordSignals.popupAbuse,
      foundFakeShoppingKeywords: categoryKeywordSignals.fakeShopping,
      foundPrizeKeywords: categoryKeywordSignals.prize,
      foundPiratedKeywords: categoryKeywordSignals.pirated,
      dataLeakSignals: extractDataLeakSignals(forms, links, buttons, iframes, scripts, domain),
      securitySignals: extractSecuritySignals(scripts, iframes, domain),
      pageKey: getPageKey(),
      ...getAdHeavySignals(images, links, safeKeywordSurface),
      timestamp: new Date().toISOString()
    };
  }

  function sendPageEvent(type, extra = {}) {
    const eventKey = `${type}:${extra.domain || window.location.hostname}`;
    // Throttle (not permanently suppress) sensitive-focus events: focusin fires
    // repeatedly, but a genuine later interaction must re-arm the correlation
    // window in the worker. A permanent per-domain dedup left only the first focus
    // able to correlate a post-interaction exfiltration request (F14).
    if (type === PASSWORD_FOCUS_MESSAGE) {
      const lastSentAt = sentPageEvents.get(eventKey) || 0;
      if (Date.now() - lastSentAt < PASSWORD_FOCUS_THROTTLE_MS) {
        return;
      }
    }

    sentPageEvents.set(eventKey, Date.now());
    chrome.runtime.sendMessage({
      type,
      payload: {
        url: sanitizeUrl(window.location.href),
        domain: window.location.hostname.toLowerCase(),
        pageKey: getPageKey(),
        navigationId: currentNavigationId,
        timestamp: new Date().toISOString(),
        ...extra
      }
    }, () => {
      chrome.runtime.lastError;
    });
  }

  function installPageEventListeners() {
    document.addEventListener("focusin", (event) => {
      const target = event.target;
      const sensitiveKind = target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) ? getSensitiveFieldKind(target) : "";
      if (sensitiveKind) {
        sendPageEvent(PASSWORD_FOCUS_MESSAGE, { sensitiveKind });
      }
    }, true);

    document.addEventListener("submit", (event) => {
      const form = event.target;
      const action = form && form.getAttribute ? sanitizeUrl(form.getAttribute("action") || window.location.href) : "";
      const actionMeta = getUrlMetadata(action || window.location.href);
      const fields = form && form.querySelectorAll ? Array.from(form.querySelectorAll("input, textarea, select")) : [];
      const sensitiveKinds = fields.map(getSensitiveFieldKind).filter(Boolean);
      sendPageEvent(FORM_SUBMITTED_MESSAGE, {
        formActionUrl: action,
        formMethod: normalizeText(form && form.method || "get").toUpperCase(),
        actionProtocol: actionMeta.protocol,
        isCrossDomainAction: Boolean(actionMeta.hostname && !isSameSiteDomain(window.location.hostname, actionMeta.hostname) && !isKnownIdentityProvider(actionMeta.hostname) && !isKnownPaymentProvider(actionMeta.hostname)),
        destinationRole: isKnownIdentityProvider(actionMeta.hostname) ? "KNOWN_IDENTITY_PROVIDER" : isKnownPaymentProvider(actionMeta.hostname) ? "KNOWN_PAYMENT_PROVIDER" : "FORM_DESTINATION",
        hasSensitiveFields: sensitiveKinds.length > 0,
        hasPasswordField: sensitiveKinds.includes("password"),
        hasOtpOrPaymentField: sensitiveKinds.some((kind) => kind === "verification" || kind === "payment"),
        sensitiveFieldCount: sensitiveKinds.length
      });
    }, true);

    document.addEventListener("click", (event) => {
      const target = event.target && event.target.closest ? event.target.closest("a, button, input[type='button'], input[type='submit'], [role='button']") : null;
      if (!target) {
        return;
      }

      const text = getElementText(target);
      const href = target.href || "";
      if (isApkHref(href) || /download|install|continue to download|download apk|install app|ดาวน์โหลด|ติดตั้ง/i.test(text)) {
        sendPageEvent(DOWNLOAD_CLICKED_MESSAGE, {
          clickedUrl: href ? sanitizeUrl(href) : "",
          isApk: isApkHref(href)
        });
      }
    }, true);
  }

  function sendScanResult(scanPhase = "FINAL") {
    const requestedPageKey = currentPageKey;
    const payload = scanPage();
    payload.scanPhase = scanPhase;
    setBadgeScanning();

    chrome.runtime.sendMessage({ type: SCAN_MESSAGE, payload }, (response) => {
      if (requestedPageKey !== currentPageKey || payload.pageKey !== getPageKey()) {
        return;
      }
      if (chrome.runtime.lastError || !response || !response.ok || !response.result) {
        updateScanBadge({
          risk: {
            score: "--",
            level: "SCANNING",
            category: "UNKNOWN",
            reasons: ["Project Argus is waiting for a scan result from the extension service worker."]
          },
          modelStatus: { mode: "LOCAL_MODEL", externalAi: false }
        });
        return;
      }

      updateScanBadge(response.result);
      currentNavigationId = response.result.navigationId || currentNavigationId;
      if (scanPhase === "PRELIMINARY" && response.result.settings && response.result.settings.progressiveScan) {
        if (finalScanTimer) window.clearTimeout(finalScanTimer);
        finalScanTimer = window.setTimeout(
          () => sendScanResult("FINAL"),
          Number(response.result.settings.observationWindowMs) || 4000
        );
      }
    });
  }

  function getPageKey() {
    try {
      const parsed = new URL(window.location.href);
      return `${parsed.origin}${parsed.pathname}#${routeFingerprint(`${parsed.search}${parsed.hash}`)}`;
    } catch (error) {
      return String(window.location.href || "");
    }
  }

  function routeFingerprint(value) {
    let hash = 2166136261;
    for (const character of String(value || "")) {
      hash ^= character.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function handlePageChange() {
    const nextPageKey = getPageKey();
    if (nextPageKey === currentPageKey) return;

    currentPageKey = nextPageKey;
    currentNavigationId = null;
    sentPageEvents.clear();
    const badge = document.getElementById(BADGE_ID);
    const panel = document.getElementById(BADGE_PANEL_ID);
    if (badge) badge.dataset.argusHasResult = "false";
    if (panel) panel.hidden = true;
    setBadgeScanning();

    chrome.runtime.sendMessage({
      type: PAGE_CHANGED_MESSAGE,
      payload: {
        pageKey: nextPageKey,
        url: sanitizeUrl(window.location.href),
        domain: window.location.hostname.toLowerCase()
      }
    }, (response) => {
      if (chrome.runtime.lastError) return;
      // Adopt the fresh navigation id immediately so sensitive events fired
      // before the first scan response are not rejected as stale.
      if (response && response.navigationId && getPageKey() === nextPageKey) {
        currentNavigationId = response.navigationId;
      }
    });

    if (pageChangeTimer) window.clearTimeout(pageChangeTimer);
    pageChangeTimer = window.setTimeout(() => sendScanResult("PRELIMINARY"), 120);
    if (finalScanTimer) window.clearTimeout(finalScanTimer);
    finalScanTimer = window.setTimeout(() => sendScanResult("FINAL"), 4000);
  }

  function installNavigationObserver() {
    ["pushState", "replaceState"].forEach((methodName) => {
      const original = window.history[methodName];
      if (typeof original !== "function" || original.__argusWrapped) return;
      const wrapped = function argusHistoryChange(...args) {
        const result = original.apply(this, args);
        queueMicrotask(handlePageChange);
        return result;
      };
      wrapped.__argusWrapped = true;
      window.history[methodName] = wrapped;
    });
    window.addEventListener("popstate", handlePageChange, true);
    window.addEventListener("hashchange", handlePageChange, true);
  }

  function showScanBadge() {
    if (document.getElementById(BADGE_ID)) {
      return;
    }

    const badge = document.createElement("button");
    badge.id = BADGE_ID;
    badge.className = "argus-scan-badge argus-risk-scanning";
    badge.type = "button";
    badge.setAttribute("aria-label", "Project Argus scan active. Risk score pending.");
    badge.setAttribute("aria-controls", BADGE_PANEL_ID);
    badge.setAttribute("aria-expanded", "false");

    const icon = document.createElement("span");
    icon.className = "argus-scan-badge-icon";
    icon.setAttribute("aria-hidden", "true");

    const mark = document.createElement("span");
    mark.className = "argus-scan-badge-mark";
    mark.textContent = "A";
    icon.appendChild(mark);

    const text = document.createElement("span");
    text.className = "argus-scan-badge-text";
    text.textContent = "Argus scanning";

    const score = document.createElement("span");
    score.className = "argus-scan-badge-score";
    score.textContent = "--/100";

    badge.appendChild(icon);
    badge.appendChild(text);
    badge.appendChild(score);
    badge.addEventListener("click", toggleScanDetails);

    document.documentElement.appendChild(badge);
    document.documentElement.appendChild(createScanDetailPanel());

    window.setTimeout(() => {
      badge.classList.add("argus-scan-badge--settled");
    }, 2800);
  }

  function createScanDetailPanel() {
    const panel = document.createElement("section");
    panel.id = BADGE_PANEL_ID;
    panel.className = "argus-scan-detail-panel";
    panel.hidden = true;
    panel.setAttribute("aria-live", "polite");
    panel.innerHTML = `
      <div class="argus-scan-detail-header">
        <div class="argus-scan-detail-title">Project Argus details</div>
        <div class="argus-scan-detail-level">Scanning</div>
      </div>
      <div class="argus-scan-detail-score-row"><span>Risk score</span><strong class="argus-scan-detail-score">--/100</strong></div>
      <div class="argus-scan-detail-source">Analysis source: waiting</div>
      <div class="argus-scan-detail-reasons-title">Why Argus thinks this</div>
      <ul class="argus-scan-detail-reasons"><li>Scan is starting.</li></ul>
      <button class="argus-report-false-positive" type="button">Report False Positive</button>
      <div class="argus-feedback-status" aria-live="polite"></div>
    `;
    panel.querySelector(".argus-report-false-positive").addEventListener("click", reportFalsePositive);
    return panel;
  }

  function reportFalsePositive() {
    const panel = document.getElementById(BADGE_PANEL_ID);
    const status = panel && panel.querySelector(".argus-feedback-status");
    if (!latestRenderedScan || !status) return;
    status.textContent = "Saving feedback...";
    chrome.runtime.sendMessage({ type: "ARGUS_REPORT_FALSE_POSITIVE", payload: latestRenderedScan }, (response) => {
      if (chrome.runtime.lastError || !response || !response.ok) {
        status.textContent = "Saved locally when the extension is available.";
        return;
      }
      const delivery = response.result && response.result.delivery;
      status.textContent = delivery && delivery.status === "SENT"
        ? "Feedback saved and sent to the local collector."
        : "Feedback saved locally and queued for the collector.";
    });
  }

  function setBadgeScanning() {
    const badge = document.getElementById(BADGE_ID);
    if (!badge || badge.dataset.argusHasResult === "true") {
      return;
    }

    updateScanBadge({
      risk: {
        score: "--",
        level: "SCANNING",
        category: "UNKNOWN",
        reasons: ["Project Argus is scanning this page for risk signals."]
      },
      modelStatus: { mode: "LOCAL_MODEL", externalAi: false }
    });
  }

  function toggleScanDetails() {
    const badge = document.getElementById(BADGE_ID);
    const panel = document.getElementById(BADGE_PANEL_ID);
    if (!badge || !panel) {
      return;
    }

    const willOpen = panel.hidden;
    panel.hidden = !willOpen;
    badge.classList.toggle("argus-scan-badge--expanded", willOpen);
    badge.setAttribute("aria-expanded", String(willOpen));
  }

  function updateScanBadge(scan) {
    const badge = document.getElementById(BADGE_ID);
    const panel = document.getElementById(BADGE_PANEL_ID);
    if (!badge || !panel) {
      return;
    }

    latestRenderedScan = scan;
    const hadFinalResult = badge.dataset.argusHasResult === "true";
    const risk = scan.risk || {};
    const score = getRiskScore(risk);
    const level = formatRiskLevel(risk.level);
    const riskClass = getRiskClass(risk.level);
    const source = scan.source || risk.source || getAnalysisSource(scan, risk);
    const reasons = Array.isArray(risk.reasons) && risk.reasons.length ? risk.reasons : ["No detailed reasons were returned for this scan."];
    const shouldHideSafeBadge = scan.settings && scan.settings.showBadgeOnSafePages === false && riskClass === "argus-risk-safe";

    if (shouldHideSafeBadge) {
      badge.hidden = true;
      panel.hidden = true;
      badge.setAttribute("aria-expanded", "false");
      return;
    }

    badge.hidden = false;

    badge.dataset.argusHasResult = score === "--" ? "false" : "true";
    badge.classList.remove("argus-risk-scanning", "argus-risk-safe", "argus-risk-monitoring", "argus-risk-suspicious", "argus-risk-high");
    badge.classList.add(riskClass);
    const observing = scan.isFinal === false;
    const displayedScore = observing ? "--" : score;
    badge.dataset.argusHasResult = observing ? "false" : badge.dataset.argusHasResult;
    badge.querySelector(".argus-scan-badge-text").textContent = observing ? "OBSERVING" : level === "SCANNING" ? "Argus scanning" : level;
    badge.querySelector(".argus-scan-badge-score").textContent = `${displayedScore}/100`;
    badge.setAttribute("aria-label", observing
      ? "Project Argus is observing page and network behavior. Final score pending."
      : `Project Argus risk score ${score} out of 100. ${level}. Click for details.`);

    panel.classList.remove("argus-risk-scanning", "argus-risk-safe", "argus-risk-monitoring", "argus-risk-suspicious", "argus-risk-high");
    panel.classList.add(riskClass);
    applyRiskPalette(panel, riskClass);
    panel.querySelector(".argus-scan-detail-level").textContent = observing ? "OBSERVING" : level;
    panel.querySelector(".argus-scan-detail-score").textContent = `${displayedScore}/100`;
    const tier = risk.decisionTier ? ` | ${risk.decisionTier.replaceAll("_", " ").toLowerCase()}` : "";
    panel.querySelector(".argus-scan-detail-source").textContent = `Analysis source: ${source}${tier}`;
    panel.querySelector(".argus-scan-detail-reasons").replaceChildren(
      ...reasons.slice(0, 6).map((reason) => {
        const item = document.createElement("li");
        item.textContent = reason;
        return item;
      })
    );

    if (!observing && !hadFinalResult) {
      panel.hidden = true;
      badge.classList.remove("argus-scan-badge--expanded");
      badge.setAttribute("aria-expanded", "false");
    }
  }

  function applyRiskPalette(panel, riskClass) {
    const palettes = {
      "argus-risk-safe": { border: "rgba(67, 209, 125, 0.72)", glow: "rgba(67, 209, 125, 0.24)", accent: "#43d17d", ink: "#06140b" },
      "argus-risk-suspicious": { border: "rgba(255, 200, 87, 0.82)", glow: "rgba(255, 200, 87, 0.3)", accent: "#ffc857", ink: "#1b1200" },
      "argus-risk-high": { border: "rgba(255, 46, 77, 0.88)", glow: "rgba(255, 46, 77, 0.36)", accent: "#ff2e4d", ink: "#ffffff" },
      "argus-risk-monitoring": { border: "rgba(112, 214, 255, 0.68)", glow: "rgba(112, 214, 255, 0.22)", accent: "#70d6ff", ink: "#07101f" },
      "argus-risk-scanning": { border: "rgba(112, 214, 255, 0.42)", glow: "rgba(112, 214, 255, 0.18)", accent: "#70d6ff", ink: "#07101f" }
    };
    const palette = palettes[riskClass] || palettes["argus-risk-scanning"];
    panel.style.setProperty("border-color", palette.border, "important");
    panel.style.setProperty("box-shadow", `0 18px 48px rgba(0, 0, 0, 0.42), 0 0 24px ${palette.glow}`, "important");
    const level = panel.querySelector(".argus-scan-detail-level");
    const score = panel.querySelector(".argus-scan-detail-score");
    const report = panel.querySelector(".argus-report-false-positive");
    if (level) {
      level.style.setProperty("background", palette.accent, "important");
      level.style.setProperty("color", palette.ink, "important");
    }
    if (score) score.style.setProperty("color", palette.accent, "important");
    if (report) report.style.setProperty("border-color", palette.border, "important");
  }

  function getRiskScore(risk) {
    const rawScore = risk.score ?? risk.riskScore;
    if (rawScore === "--") {
      return "--";
    }

    const value = Number(rawScore);
    return Number.isFinite(value) ? Math.round(value) : "--";
  }

  function getRiskClass(level) {
    const normalized = String(level || "").trim().toUpperCase().replace(/\s+/g, "_");
    if (normalized === "HIGH_RISK") {
      return "argus-risk-high";
    }
    if (normalized === "SUSPICIOUS") {
      return "argus-risk-suspicious";
    }
    if (normalized === "MONITORING" || normalized === "UNCERTAIN") {
      return "argus-risk-monitoring";
    }
    if (normalized === "SAFE") {
      return "argus-risk-safe";
    }
    return "argus-risk-scanning";
  }

  function getAnalysisSource(scan, risk) {
    if (risk.source) {
      return risk.source;
    }
    if (scan.modelStatus && scan.modelStatus.mode) {
      return scan.modelStatus.mode;
    }
    return "LOCAL_MODEL";
  }

  function formatRiskLevel(level) {
    const formatted = String(level || "SAFE").replace(/_/g, " ").trim();
    return formatted.toUpperCase() === "SCANNING" ? "Scanning" : formatted.toUpperCase();
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (!message || !message.type) {
      return;
    }

    if (message.type === RESCAN_MESSAGE) {
      sendScanResult(message.scanPhase || "FINAL");
    }
  });

  function startArgusScan() {
    installPageEventListeners();
    installNavigationObserver();
    showScanBadge();
    sendScanResult("PRELIMINARY");
    finalScanTimer = window.setTimeout(() => sendScanResult("FINAL"), 4000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startArgusScan, { once: true });
  } else {
    startArgusScan();
  }

}());
