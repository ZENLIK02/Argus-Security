(function () {
  const SCAN_MESSAGE = "ARGUS_PAGE_SCAN";
  const WARNING_MESSAGE = "ARGUS_SHOW_WARNING";
  const RESCAN_MESSAGE = "ARGUS_RESCAN_PAGE";
  const PASSWORD_FOCUS_MESSAGE = "ARGUS_PASSWORD_FIELD_FOCUSED";
  const FORM_SUBMITTED_MESSAGE = "ARGUS_FORM_SUBMITTED";
  const DOWNLOAD_CLICKED_MESSAGE = "ARGUS_DOWNLOAD_CLICKED";
  const OVERLAY_ID = "argus-warning-overlay";
  const BADGE_ID = "argus-scan-badge";
  const BADGE_PANEL_ID = "argus-scan-detail-panel";
  let lastDemoWarningSignature = "";
  const sentPageEvents = new Set();

  const TRUSTED_DOMAINS = [
    "google.com", "www.google.com", "google.co.th", "www.google.co.th", "play.google.com", "accounts.google.com",
    "youtube.com", "roblox.com", "create.roblox.com", "finance.yahoo.com",
    "yahoo.com", "samsung.com", "www.samsung.com", "galaxystore.samsung.com",
    "apps.samsung.com", "apple.com", "apps.apple.com", "github.com",
    "microsoft.com", "tiktok.com",
    "instagram.com", "facebook.com", "x.com", "twitter.com", "linkedin.com",
    "reddit.com", "discord.com", "steamcommunity.com", "steampowered.com",
    "epicgames.com", "store.epicgames.com", "mit.edu", "ieee.org", "arxiv.org",
    "kbank.co.th", "kasikornbank.com", "scb.co.th", "bangkokbank.com",
    "krungsri.com", "set.or.th", "sec.or.th", "bot.or.th"
  ];

  const SEARCH_ENGINE_DOMAINS = [
    "google.com",
    "www.google.com",
    "bing.com",
    "www.bing.com",
    "search.brave.com",
    "duckduckgo.com",
    "www.duckduckgo.com"
  ];

  const KEYWORDS = {
    otp: ["otp", "one-time password", "one time password", "verification code", "verify code", "security code", "2fa", "mfa"],
    login: ["login", "log in", "sign in", "verify account", "account verification", "account center", "member login", "เข้าสู่ระบบ", "สมัครสมาชิก", "ยืนยันบัญชี"],
    appStore: ["google play", "play store", "galaxy store", "samsung store", "app store", "install app", "update app"],
    gambling: ["casino", "gambling", "betting", "sportsbook", "slot", "slots", "poker", "baccarat", "jackpot", "ufa", "pgslot", "sbobet", "บาคาร่า", "คาสิโน", "สล็อต", "พนัน", "เว็บพนัน", "เดิมพัน", "แทงบอล", "หวย", "รูเล็ต", "ฝากถอน", "เครดิตฟรี", "โปรโมชั่น", "แจ็คพอต"],
    adult: ["adult", "18+", "xxx", "porn", "sex", "onlyfans", "คลิปหลุด", "เว็บโป๊", "หนังโป๊"],
    banking: ["bank", "mobile banking", "verify bank account", "account locked", "transfer", "wallet", "ธนาคาร", "บัญชีถูกล็อก", "โอนเงิน", "พร้อมเพย์"],
    investment: ["guaranteed profit", "double your money", "crypto bonus", "fast return", "wallet connect", "ลงทุน", "กำไรแน่นอน", "ถอนเงินทันที", "คริปโต"],
    techSupport: ["your device is infected", "call support", "virus detected", "security alert", "remote support", "pc cleaner"],
    popupAbuse: ["allow notifications", "click allow", "continue to download", "your phone is infected", "download now", "skip ad", "fake download", "กดอนุญาต", "กดข้ามโฆษณา"],
    fakeShopping: ["flash sale", "90% off", "limited offer", "official sale", "brand outlet", "clearance sale", "ของแท้ราคาถูก"],
    prize: ["you won", "claim reward", "free iphone", "lucky winner", "giveaway", "รับรางวัล", "ของแจก"],
    pirated: ["crack", "keygen", "serial key", "free premium", "patched", "mod apk"],
    ad: ["ad", "ads", "advert", "advertisement", "banner", "sponsor", "sponsored", "promo", "promotion", "popup", "pop-up", "affiliate", "โฆษณา", "สมัครคลิก", "เครดิตฟรี", "ฝากถอน", "ชวนเพื่อน", "รับเงินคืน"]
  };

  const SUSPICIOUS_DOMAIN_WORDS = [
    "verify", "secure", "update", "login", "account", "wallet", "bank",
    "play-store", "google-play", "galaxy-store", "apk", "support-secure"
  ];

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

    return domain === otherDomain || domain.endsWith(`.${otherDomain}`) || otherDomain.endsWith(`.${domain}`);
  }

  function isTrustedDomain(domain) {
    return TRUSTED_DOMAINS.some((trustedDomain) => isDomainMatch(domain, trustedDomain));
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
    let passwordCrossDomainForm = false;
    let otpOrPaymentCrossDomainForm = false;
    let passwordHttpForm = false;
    let otpOrPaymentHttpForm = false;
    const evasiveBehaviorSignals = extractEvasiveBehaviorSignals(forms, links, buttons, iframes, scripts, currentDomain);

    forms.forEach((form) => {
      const rawAction = (form.getAttribute("action") || "").trim();
      if (!rawAction) {
        emptyFormActionCount += 1;
        return;
      }

      const actionMeta = getUrlMetadata(rawAction);
      if (!actionMeta.sanitizedUrl) {
        return;
      }

      formActionUrls.push(actionMeta.sanitizedUrl);

      const isHttpAction = actionMeta.protocol === "http:";
      const isCrossDomainAction = actionMeta.hostname && !isSameSiteDomain(currentDomain, actionMeta.hostname);
      const formInputs = Array.from(form.querySelectorAll("input, textarea, select"));
      const hasPasswordInForm = formInputs.some((input) => normalizeText(input.type) === "password");
      const hasOtpPaymentBankField = formInputs.some((input) => {
        const surface = getInputSurface(input);
        return (
          collectKeywordMatches(surface, KEYWORDS.otp).length > 0 ||
          collectKeywordMatches(surface, KEYWORDS.banking).length > 0 ||
          /card|credit|payment|deposit|amount|wallet|bank|บัญชี|ฝาก|ถอน|โอน/i.test(surface)
        );
      });

      if (isHttpAction) {
        httpFormActionCount += 1;
      }

      if (isCrossDomainAction) {
        crossDomainFormActionCount += 1;
        passwordCrossDomainForm = passwordCrossDomainForm || hasPasswordInForm;
        otpOrPaymentCrossDomainForm = otpOrPaymentCrossDomainForm || hasOtpPaymentBankField;
      }

      passwordHttpForm = passwordHttpForm || (isHttpAction && hasPasswordInForm);
      otpOrPaymentHttpForm = otpOrPaymentHttpForm || (isHttpAction && hasOtpPaymentBankField);
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
      formActionUrls: unique(formActionUrls).slice(0, 30),
      emptyFormActionCount,
      httpFormActionCount,
      crossDomainFormActionCount,
      passwordCrossDomainForm,
      otpOrPaymentCrossDomainForm,
      passwordHttpForm,
      otpOrPaymentHttpForm,
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
      preventedSubmitIndicator,
      localFormWithJsSinkIndicator,
      credentialLikeTextFieldCount,
      sensitiveTextareaCount,
      deceptiveLowFrictionContent
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
      ...getAdHeavySignals(images, links, safeKeywordSurface),
      timestamp: new Date().toISOString()
    };
  }

  function sendPageEvent(type, extra = {}) {
    const eventKey = `${type}:${extra.domain || window.location.hostname}`;
    if (type === PASSWORD_FOCUS_MESSAGE && sentPageEvents.has(eventKey)) {
      return;
    }

    sentPageEvents.add(eventKey);
    chrome.runtime.sendMessage({
      type,
      payload: {
        url: sanitizeUrl(window.location.href),
        domain: window.location.hostname.toLowerCase(),
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
      if (target && target.tagName === "INPUT" && normalizeText(target.type) === "password") {
        sendPageEvent(PASSWORD_FOCUS_MESSAGE);
      }
    }, true);

    document.addEventListener("submit", (event) => {
      const form = event.target;
      const action = form && form.getAttribute ? sanitizeUrl(form.getAttribute("action") || window.location.href) : "";
      sendPageEvent(FORM_SUBMITTED_MESSAGE, { formActionUrl: action });
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

  function sendScanResult() {
    const payload = scanPage();
    setBadgeScanning();

    chrome.runtime.sendMessage({ type: SCAN_MESSAGE, payload }, (response) => {
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
    });
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
    `;
    return panel;
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
    badge.classList.remove("argus-risk-scanning", "argus-risk-safe", "argus-risk-suspicious", "argus-risk-high");
    badge.classList.add(riskClass);
    badge.querySelector(".argus-scan-badge-text").textContent = level === "SCANNING" ? "Argus scanning" : level;
    badge.querySelector(".argus-scan-badge-score").textContent = `${score}/100`;
    badge.setAttribute("aria-label", `Project Argus risk score ${score} out of 100. ${level}. Click for details.`);

    panel.classList.remove("argus-risk-scanning", "argus-risk-safe", "argus-risk-suspicious", "argus-risk-high");
    panel.classList.add(riskClass);
    panel.querySelector(".argus-scan-detail-level").textContent = level;
    panel.querySelector(".argus-scan-detail-score").textContent = `${score}/100`;
    panel.querySelector(".argus-scan-detail-source").textContent = `Analysis source: ${source}`;
    panel.querySelector(".argus-scan-detail-reasons").replaceChildren(
      ...reasons.slice(0, 6).map((reason) => {
        const item = document.createElement("li");
        item.textContent = reason;
        return item;
      })
    );
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

  function appendText(parent, tagName, className, text) {
    const element = document.createElement(tagName);
    element.className = className;
    element.textContent = text;
    parent.appendChild(element);
    return element;
  }

  function showWarning(risk) {
    const warningSignature = JSON.stringify({
      score: getRiskScore(risk),
      level: risk.level,
      category: risk.category,
      reasons: Array.isArray(risk.reasons) ? risk.reasons.slice(0, 3) : []
    });

    if ((risk.demoMode || (risk.settings && risk.settings.demoMode)) && warningSignature === lastDemoWarningSignature && document.getElementById(OVERLAY_ID)) {
      return;
    }

    lastDemoWarningSignature = warningSignature;
    const oldOverlay = document.getElementById(OVERLAY_ID);
    if (oldOverlay) {
      oldOverlay.remove();
    }

    const overlay = document.createElement("aside");
    overlay.id = OVERLAY_ID;
    overlay.className = "argus-warning-overlay";
    overlay.setAttribute("role", "alertdialog");
    overlay.setAttribute("aria-live", "assertive");
    overlay.setAttribute("aria-label", "Project Argus warning");

    const card = document.createElement("div");
    card.className = "argus-warning-card";
    overlay.appendChild(card);

    appendText(card, "div", "argus-warning-kicker", "Project Argus Warning");
    appendText(card, "h2", "argus-warning-title", formatRiskLevel(risk.level));
    appendText(card, "p", "argus-warning-message", "This page has risk indicators. Review the reasons before entering sensitive information or downloading files.");

    const scoreRow = document.createElement("div");
    scoreRow.className = "argus-warning-score-row";
    card.appendChild(scoreRow);
    appendText(scoreRow, "span", "argus-warning-score-label", risk.category || "UNKNOWN");
    appendText(scoreRow, "strong", "argus-warning-score", `${getRiskScore(risk)}/100`);

    const reasonsTitle = appendText(card, "div", "argus-warning-reasons-title", "Top reasons");
    reasonsTitle.id = "argus-warning-reasons-title";
    const reasonsList = document.createElement("ul");
    reasonsList.className = "argus-warning-reasons";
    reasonsList.setAttribute("aria-labelledby", reasonsTitle.id);
    card.appendChild(reasonsList);

    (risk.reasons && risk.reasons.length ? risk.reasons : ["Suspicious page behavior detected."])
      .slice(0, 3)
      .forEach((reason) => appendText(reasonsList, "li", "argus-warning-reason", reason));

    const actions = document.createElement("div");
    actions.className = "argus-warning-actions";
    card.appendChild(actions);

    const goBack = document.createElement("button");
    goBack.type = "button";
    goBack.className = "argus-warning-action argus-warning-action-primary";
    goBack.textContent = "Go Back";
    goBack.addEventListener("click", () => window.history.back());
    actions.appendChild(goBack);

    const continueAnyway = document.createElement("button");
    continueAnyway.type = "button";
    continueAnyway.className = "argus-warning-action";
    continueAnyway.textContent = "Continue Anyway";
    continueAnyway.addEventListener("click", () => overlay.remove());
    actions.appendChild(continueAnyway);

    const report = document.createElement("button");
    report.type = "button";
    report.className = "argus-warning-action";
    report.textContent = "Report False Positive";
    report.addEventListener("click", () => {
      chrome.runtime.sendMessage({
        type: "ARGUS_REPORT_FALSE_POSITIVE",
        payload: {
          domain: window.location.hostname,
          score: getRiskScore(risk),
          level: risk.level,
          category: risk.category,
          reasons: Array.isArray(risk.reasons) ? risk.reasons.slice(0, 8) : [],
          timestamp: new Date().toISOString()
        }
      });
      report.textContent = "Reported";
      report.disabled = true;
    });
    actions.appendChild(report);

    document.documentElement.appendChild(overlay);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (!message || !message.type) {
      return;
    }

    if (message.type === WARNING_MESSAGE) {
      showWarning(message.payload);
    }

    if (message.type === RESCAN_MESSAGE) {
      sendScanResult();
    }
  });

  function startArgusScan() {
    installPageEventListeners();
    showScanBadge();
    sendScanResult();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startArgusScan, { once: true });
  } else {
    startArgusScan();
  }

  setTimeout(sendScanResult, 1500);
  setTimeout(sendScanResult, 4000);
}());
