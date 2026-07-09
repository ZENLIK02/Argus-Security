const SCAN_MESSAGE = "ARGUS_PAGE_SCAN";
const WARNING_MESSAGE = "ARGUS_SHOW_WARNING";
const GET_LATEST_MESSAGE = "ARGUS_GET_LATEST_SCAN";
const RESCAN_MESSAGE = "ARGUS_RESCAN_PAGE";
const REPORT_FALSE_POSITIVE_MESSAGE = "ARGUS_REPORT_FALSE_POSITIVE";
const CLEAR_LAST_SCAN_MESSAGE = "ARGUS_CLEAR_LAST_SCAN";
const PASSWORD_FOCUS_MESSAGE = "ARGUS_PASSWORD_FIELD_FOCUSED";
const FORM_SUBMITTED_MESSAGE = "ARGUS_FORM_SUBMITTED";
const DOWNLOAD_CLICKED_MESSAGE = "ARGUS_DOWNLOAD_CLICKED";
const SETTINGS_KEY = "argusSettings";

const CONTENT_RISK_MIN_SCORE = 35;

const GAMBLING_DOMAIN_PATTERNS = [
  "casino", "slot", "bet", "jackpot", "ufa", "pgslot", "sbobet", "game66", "mahagame", "hydra888", "kingdom66", "lockdown168"
];

const ADULT_DOMAIN_PATTERNS = [
  "porn", "xxx", "adult", "18plus"
];

const DEFAULT_SETTINGS = {
  warningThreshold: 35,
  showBadgeOnSafePages: true,
  demoMode: true
};

let trustedDomainsCache = null;
let riskyCategoriesCache = null;
const tabNetworkSignals = new Map();
const tabPageDomains = new Map();

initializeNetworkMonitoring();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    return false;
  }

  if (message.type === SCAN_MESSAGE) {
    handlePageScan(message.payload, sender)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === GET_LATEST_MESSAGE) {
    getLatestScan(message.tabId)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === REPORT_FALSE_POSITIVE_MESSAGE) {
    saveFalsePositiveReport(message.payload)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === CLEAR_LAST_SCAN_MESSAGE) {
    clearLastScan(message.tabId)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if ([PASSWORD_FOCUS_MESSAGE, FORM_SUBMITTED_MESSAGE, DOWNLOAD_CLICKED_MESSAGE].includes(message.type)) {
    recordPageEvent(message.type, message.payload, sender);
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

function initializeNetworkMonitoring() {
  if (!chrome.webRequest || !chrome.webRequest.onBeforeRequest) {
    console.warn("[Project Argus] chrome.webRequest is unavailable; network metadata monitoring disabled.");
    return;
  }

  chrome.webRequest.onBeforeRequest.addListener(
    recordNetworkRequest,
    { urls: ["<all_urls>"] }
  );

  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      tabNetworkSignals.delete(tabId);
      tabPageDomains.delete(tabId);
    });
  }

  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
      if (changeInfo.status === "loading") {
        tabNetworkSignals.delete(tabId);
        tabPageDomains.delete(tabId);
      }
    });
  }
}

function recordNetworkRequest(details) {
  if (!details || details.tabId < 0) {
    return;
  }

  const requestMeta = parseUrlMetadata(details.url);
  if (!requestMeta.hostname) {
    return;
  }

  const tabDomain = tabPageDomains.get(details.tabId) || getInitiatorDomain(details.initiator || details.documentUrl || "");
  const initiatorDomain = getInitiatorDomain(details.initiator || details.documentUrl || "");
  const referenceDomain = tabDomain || initiatorDomain;
  const isThirdParty = referenceDomain ? !isDomainMatch(requestMeta.hostname, referenceDomain) : false;
  const signals = getNetworkSignals(details.tabId);
  const now = Date.now();

  signals.totalRequests += 1;
  if (isThirdParty) {
    signals.thirdPartyRequests += 1;
  }
  if (requestMeta.protocol === "http:") {
    signals.insecureHttpRequests += 1;
  }

  if (isThirdParty && details.type === "script") {
    signals.thirdPartyScriptRequests += 1;
  }
  if (isThirdParty && (details.type === "sub_frame" || details.type === "object")) {
    signals.thirdPartyFrameRequests += 1;
  }
  if (isThirdParty && ["xmlhttprequest", "fetch", "beacon", "ping"].includes(details.type)) {
    signals.thirdPartyXHRRequests += 1;
  }
  if (signals.lastFormSubmitAt && now - signals.lastFormSubmitAt < 15000 && isThirdParty) {
    signals.requestsAfterFormSubmit += 1;
  }
  if (signals.lastPasswordFocusAt && now - signals.lastPasswordFocusAt < 15000 && isThirdParty) {
    signals.requestsAfterPasswordFocus += 1;
  }
  if (isThirdParty && isSuspiciousRequestType(details.type)) {
    addLimited(signals.suspiciousRequestDomains, requestMeta.hostname, 30);
  }

  signals.updatedAt = now;
  tabNetworkSignals.set(details.tabId, signals);
}

function recordPageEvent(type, payload, sender) {
  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (!tabId) {
    return;
  }

  const signals = getNetworkSignals(tabId);
  const now = Date.now();
  if (type === PASSWORD_FOCUS_MESSAGE) {
    signals.lastPasswordFocusAt = now;
  }
  if (type === FORM_SUBMITTED_MESSAGE) {
    signals.lastFormSubmitAt = now;
  }
  if (type === DOWNLOAD_CLICKED_MESSAGE) {
    signals.downloadClickCount += 1;
  }
  signals.updatedAt = now;
  tabNetworkSignals.set(tabId, signals);
}

function getNetworkSignals(tabId) {
  const current = tabNetworkSignals.get(tabId);
  if (current) {
    return current;
  }

  return {
    totalRequests: 0,
    thirdPartyRequests: 0,
    thirdPartyScriptRequests: 0,
    thirdPartyFrameRequests: 0,
    thirdPartyXHRRequests: 0,
    insecureHttpRequests: 0,
    suspiciousRequestDomains: [],
    requestsAfterFormSubmit: 0,
    requestsAfterPasswordFocus: 0,
    downloadClickCount: 0,
    lastFormSubmitAt: 0,
    lastPasswordFocusAt: 0,
    updatedAt: Date.now()
  };
}

function exportNetworkSignals(tabId) {
  const signals = getNetworkSignals(tabId);
  return {
    totalRequests: signals.totalRequests,
    thirdPartyRequests: signals.thirdPartyRequests,
    thirdPartyScriptRequests: signals.thirdPartyScriptRequests,
    thirdPartyFrameRequests: signals.thirdPartyFrameRequests,
    thirdPartyXHRRequests: signals.thirdPartyXHRRequests,
    insecureHttpRequests: signals.insecureHttpRequests,
    requestsAfterFormSubmit: signals.requestsAfterFormSubmit,
    requestsAfterPasswordFocus: signals.requestsAfterPasswordFocus,
    suspiciousRequestDomains: signals.suspiciousRequestDomains.slice(0, 30)
  };
}

async function handlePageScan(pageData, sender) {
  const tabId = sender && sender.tab ? sender.tab.id : null;
  const settings = await loadSettings();
  const trustedDomains = await loadTrustedDomains();
  const riskyCategories = await loadRiskyCategories();
  const signals = normalizeSignals(pageData, trustedDomains);
  if (tabId) {
    tabPageDomains.set(tabId, signals.domain);
    signals.networkSignals = exportNetworkSignals(tabId);
  }
  const ruleRisk = calculateRuleRisk(signals, riskyCategories);
  const modelStatus = {
    mode: "LOCAL_MODEL",
    externalAi: false,
    message: "Project Argus local model active."
  };

  const finalRisk = {
    ...ruleRisk,
    source: "LOCAL_MODEL"
  };

  const shouldWarn = shouldShowWarning(finalRisk, signals, settings);
  finalRisk.shouldWarn = shouldWarn;
  finalRisk.demoMode = settings.demoMode;

  const scanResult = {
    ...signals,
    tabId,
    risk: finalRisk,
    ruleBasedRisk: ruleRisk,
    modelStatus,
    settings: publicSettings(settings),
    source: finalRisk.source,
    debug: {
      domain: signals.domain,
      isTrustedDomain: signals.isTrustedDomain,
      isSearchEnginePage: signals.isSearchEnginePage,
      ruleScore: ruleRisk.score,
      finalScore: finalRisk.score,
      finalLevel: finalRisk.level,
      model: "LOCAL_MODEL",
      warningThreshold: settings.warningThreshold
    }
  };

  console.log("[Project Argus] scan", scanResult.debug);
  console.log("[Project Argus] signals", {
    apkLinks: signals.apkLinks.length,
    foundStoreKeywords: signals.foundStoreKeywords,
    contentRiskSignals: signals.contentRiskSignals,
    suspiciousDomainSignals: signals.suspiciousDomainSignals
  });

  await saveScanResult(scanResult);

  if (tabId && shouldWarn) {
    chrome.tabs.sendMessage(tabId, {
      type: WARNING_MESSAGE,
      payload: {
        ...finalRisk,
        settings: scanResult.settings
      }
    });
  }

  return scanResult;
}

async function loadTrustedDomains() {
  if (trustedDomainsCache) {
    return trustedDomainsCache;
  }

  trustedDomainsCache = await fetchJson("trusted_domains.json", []);
  return trustedDomainsCache;
}

async function loadRiskyCategories() {
  if (riskyCategoriesCache) {
    return riskyCategoriesCache;
  }

  riskyCategoriesCache = await fetchJson("risky_categories.json", { categories: [] });
  return riskyCategoriesCache;
}

async function fetchJson(path, fallback) {
  try {
    const response = await fetch(chrome.runtime.getURL(path));
    if (!response.ok) {
      return fallback;
    }
    return await response.json();
  } catch (error) {
    console.warn("[Project Argus] failed to load", path, error);
    return fallback;
  }
}

async function loadSettings() {
  try {
    const stored = await chrome.storage.local.get([SETTINGS_KEY]);
    return normalizeSettings(stored[SETTINGS_KEY]);
  } catch (error) {
    console.warn("[Project Argus] failed to load settings", error);
    return { ...DEFAULT_SETTINGS };
  }
}

function normalizeSettings(settings) {
  const raw = settings && typeof settings === "object" ? settings : {};
  const warningThreshold = Math.max(0, Math.min(100, Math.round(Number(raw.warningThreshold ?? DEFAULT_SETTINGS.warningThreshold))));

  return {
    warningThreshold,
    showBadgeOnSafePages: raw.showBadgeOnSafePages !== false,
    demoMode: raw.demoMode !== false
  };
}

function publicSettings(settings) {
  return {
    warningThreshold: settings.warningThreshold,
    showBadgeOnSafePages: settings.showBadgeOnSafePages,
    demoMode: settings.demoMode
  };
}

function normalizeSignals(data, trustedDomains) {
  const pageData = data || {};
  const domain = String(pageData.domain || "").toLowerCase();
  const url = String(pageData.url || "");
  const pathname = String(pageData.pathname || "/");
  const apkLinks = Array.isArray(pageData.apkLinks) ? pageData.apkLinks : [];
  const foundStoreKeywords = toArray(pageData.foundStoreKeywords);
  const foundGamblingKeywords = toArray(pageData.foundGamblingKeywords);
  const foundAdultKeywords = toArray(pageData.foundAdultKeywords);
  const foundBankingKeywords = toArray(pageData.foundBankingKeywords);
  const foundInvestmentKeywords = toArray(pageData.foundInvestmentKeywords);
  const foundTechSupportKeywords = toArray(pageData.foundTechSupportKeywords);
  const foundPopupAbuseKeywords = toArray(pageData.foundPopupAbuseKeywords);
  const foundFakeShoppingKeywords = toArray(pageData.foundFakeShoppingKeywords);
  const foundPrizeKeywords = toArray(pageData.foundPrizeKeywords);
  const foundPiratedKeywords = toArray(pageData.foundPiratedKeywords);
  const suspiciousDomainSignals = toArray(pageData.suspiciousDomainSignals).concat(getSuspiciousDomainSignals(domain));
  const domainCategorySignals = getDomainCategorySignals(domain);
  const dataLeakSignals = normalizeDataLeakSignals(pageData.dataLeakSignals);
  const trustedByFile = trustedDomains.some((trustedDomain) => isDomainMatch(domain, trustedDomain));
  const isTrusted = Boolean(pageData.isTrustedDomain) || trustedByFile;
  const isSearchEngine = Boolean(pageData.isSearchEnginePage) || isSearchEnginePage(url, domain, pathname);
  const contentRiskSignals = [];

  if (foundGamblingKeywords.length > 0) {
    contentRiskSignals.push(`Gambling keywords: ${foundGamblingKeywords.slice(0, 5).join(", ")}.`);
  }
  if (domainCategorySignals.gambling.length > 0) {
    contentRiskSignals.push(`Gambling-style domain pattern: ${domainCategorySignals.gambling.slice(0, 3).join(", ")}.`);
  }
  if (foundAdultKeywords.length > 0) {
    contentRiskSignals.push(`Adult content keywords: ${foundAdultKeywords.slice(0, 5).join(", ")}.`);
  }
  if (domainCategorySignals.adult.length > 0) {
    contentRiskSignals.push(`Adult-content domain pattern: ${domainCategorySignals.adult.slice(0, 3).join(", ")}.`);
  }
  if (foundPopupAbuseKeywords.length > 0) {
    contentRiskSignals.push(`Popup or notification abuse keywords: ${foundPopupAbuseKeywords.slice(0, 5).join(", ")}.`);
  }

  return {
    url,
    domain,
    pathname,
    isTrustedDomain: isTrusted,
    isSearchEnginePage: isSearchEngine,
    passwordFieldCount: Number(pageData.passwordFieldCount) || 0,
    hasPasswordField: Boolean(pageData.hasPasswordField) || Number(pageData.passwordFieldCount) > 0,
    hasOTP: Boolean(pageData.hasOTP),
    hasLoginKeyword: Boolean(pageData.hasLoginKeyword),
    apkLinks,
    buttonTexts: toArray(pageData.buttonTexts),
    anchorHrefs: toArray(pageData.anchorHrefs),
    foundStoreKeywords,
    suspiciousDomainSignals: unique(suspiciousDomainSignals),
    foundGamblingKeywords,
    foundAdultKeywords,
    foundBankingKeywords,
    foundInvestmentKeywords,
    foundTechSupportKeywords,
    foundPopupAbuseKeywords,
    foundFakeShoppingKeywords,
    foundPrizeKeywords,
    foundPiratedKeywords,
    domainCategorySignals,
    dataLeakSignals,
    networkSignals: normalizeNetworkSignals(pageData.networkSignals),
    contentRiskSignals,
    hasAdHeavySignal: Boolean(pageData.hasAdHeavySignal),
    adHeavySignals: toArray(pageData.adHeavySignals),
    foundAdKeywords: toArray(pageData.foundAdKeywords),
    largeImageCount: Number(pageData.largeImageCount) || 0,
    linkedLargeImageCount: Number(pageData.linkedLargeImageCount) || 0,
    fixedOrStickyElementCount: Number(pageData.fixedOrStickyElementCount) || 0,
    iframeCount: Number(pageData.iframeCount) || 0,
    externalLinkCount: Number(pageData.externalLinkCount) || 0
  };
}

function normalizeDataLeakSignals(value) {
  const raw = value && typeof value === "object" ? value : {};
  return {
    formCount: Number(raw.formCount) || 0,
    formActionUrls: toArray(raw.formActionUrls).slice(0, 30),
    emptyFormActionCount: Number(raw.emptyFormActionCount) || 0,
    httpFormActionCount: Number(raw.httpFormActionCount) || 0,
    crossDomainFormActionCount: Number(raw.crossDomainFormActionCount) || 0,
    passwordCrossDomainForm: Boolean(raw.passwordCrossDomainForm),
    otpOrPaymentCrossDomainForm: Boolean(raw.otpOrPaymentCrossDomainForm),
    passwordHttpForm: Boolean(raw.passwordHttpForm),
    otpOrPaymentHttpForm: Boolean(raw.otpOrPaymentHttpForm),
    hiddenInputCount: Number(raw.hiddenInputCount) || 0,
    hiddenIframeCount: Number(raw.hiddenIframeCount) || 0,
    externalScriptCount: Number(raw.externalScriptCount) || 0,
    thirdPartyIframeCount: Number(raw.thirdPartyIframeCount) || 0,
    redirectAwayLinkCount: Number(raw.redirectAwayLinkCount) || 0,
    thirdPartyApkLinks: toArray(raw.thirdPartyApkLinks).slice(0, 20),
    httpApkLinks: toArray(raw.httpApkLinks).slice(0, 20),
    fakeDownloadButtonNearEmbed: Boolean(raw.fakeDownloadButtonNearEmbed),
    externalScriptDomains: toArray(raw.externalScriptDomains).slice(0, 20),
    thirdPartyIframeDomains: toArray(raw.thirdPartyIframeDomains).slice(0, 20),
    redirectAwayDomains: toArray(raw.redirectAwayDomains).slice(0, 20)
  };
}

function normalizeNetworkSignals(value) {
  const raw = value && typeof value === "object" ? value : {};
  return {
    totalRequests: Number(raw.totalRequests) || 0,
    thirdPartyRequests: Number(raw.thirdPartyRequests) || 0,
    thirdPartyScriptRequests: Number(raw.thirdPartyScriptRequests) || 0,
    thirdPartyFrameRequests: Number(raw.thirdPartyFrameRequests) || 0,
    thirdPartyXHRRequests: Number(raw.thirdPartyXHRRequests) || 0,
    insecureHttpRequests: Number(raw.insecureHttpRequests) || 0,
    requestsAfterFormSubmit: Number(raw.requestsAfterFormSubmit) || 0,
    requestsAfterPasswordFocus: Number(raw.requestsAfterPasswordFocus) || 0,
    suspiciousRequestDomains: toArray(raw.suspiciousRequestDomains).slice(0, 30)
  };
}

function calculateRuleRisk(signals, categoryConfig) {
  const reasons = [];
  const categoryScores = {};
  const configuredCategoryIds = new Set((categoryConfig.categories || []).map((category) => category.id));
  const dataLeak = signals.dataLeakSignals;
  const network = signals.networkSignals;

  const strongDanger = hasStrongDangerSignals(signals);

  if (signals.isSearchEnginePage && !strongDanger) {
    return buildRisk(0, "SAFE", "SAFE", ["Official search engine result page without concrete danger signals."], "LOCAL_MODEL");
  }

  if (isOfficialAppStore(signals.domain) && signals.apkLinks.length === 0 && !signals.hasPasswordField && !signals.hasOTP) {
    return buildRisk(0, "SAFE", "SAFE", ["Official app store domain without direct APK or credential collection."], "LOCAL_MODEL");
  }

  if (!signals.isTrustedDomain) {
    if (signals.domain.length > 35) {
      addScore(categoryScores, "BRAND_IMPERSONATION", 10);
      reasons.push("Domain is unusually long.");
    }

    if ((signals.domain.match(/-/g) || []).length >= 2) {
      addScore(categoryScores, "BRAND_IMPERSONATION", 15);
      reasons.push("Domain contains multiple hyphens.");
    }

    if (signals.suspiciousDomainSignals.length > 0) {
      addScore(categoryScores, "BRAND_IMPERSONATION", 15);
      reasons.push(...signals.suspiciousDomainSignals.slice(0, 4));
    }

    if (hasBrandImpersonationPattern(signals.domain)) {
      addScore(categoryScores, "BRAND_IMPERSONATION", 25);
      reasons.push("Domain resembles a known brand impersonation pattern.");
    }
  }

  if (!signals.isTrustedDomain && signals.hasPasswordField) {
    addScore(categoryScores, "PHISHING_LOGIN", 25);
    reasons.push("Password field found on an untrusted domain.");
  }

  if (!signals.isTrustedDomain && signals.hasOTP) {
    addScore(categoryScores, "PHISHING_LOGIN", 25);
    reasons.push("OTP or verification-code signal found on an untrusted domain.");
  }

  if (!signals.isTrustedDomain && signals.hasLoginKeyword) {
    addScore(categoryScores, "PHISHING_LOGIN", 15);
    reasons.push("Login or account-verification language found on an untrusted domain.");
  }

  if (!signals.isTrustedDomain && signals.foundStoreKeywords.length > 0) {
    addScore(categoryScores, "FAKE_APP_STORE", 25);
    reasons.push(`App-store keywords on untrusted domain: ${signals.foundStoreKeywords.slice(0, 5).join(", ")}.`);
  }

  if (signals.apkLinks.length > 0) {
    addScore(categoryScores, "MALICIOUS_APK", 35);
    reasons.push(`Actual .apk href detected (${signals.apkLinks.length}).`);
  }

  if (!signals.isTrustedDomain && signals.foundStoreKeywords.length > 0 && signals.apkLinks.length > 0) {
    addScore(categoryScores, "FAKE_APP_STORE", 25);
    reasons.push("App-store keywords appear together with an actual APK link.");
  }

  if (!signals.isTrustedDomain && signals.foundBankingKeywords.length > 0 && signals.hasPasswordField) {
    addScore(categoryScores, "FAKE_BANKING", 30);
    reasons.push("Banking keywords appear with a password field on an untrusted domain.");
  }

  if (!signals.isTrustedDomain && signals.foundBankingKeywords.length > 0 && signals.hasOTP) {
    addScore(categoryScores, "FAKE_BANKING", 30);
    reasons.push("Banking keywords appear with OTP signals on an untrusted domain.");
  }

  if (!signals.isTrustedDomain && dataLeak.crossDomainFormActionCount > 0) {
    addScore(categoryScores, "DATA_EXFILTRATION", 25);
    reasons.push("This form may send sensitive information to a different domain.");
  }

  if (!signals.isTrustedDomain && dataLeak.passwordCrossDomainForm) {
    addScore(categoryScores, "DATA_EXFILTRATION", 50);
    reasons.push("Password field is inside a form that submits to a different domain.");
  }

  if (!signals.isTrustedDomain && dataLeak.otpOrPaymentCrossDomainForm) {
    addScore(categoryScores, "DATA_EXFILTRATION", 60);
    reasons.push("OTP, payment, or bank-like fields may submit to a different domain.");
  }

  if (dataLeak.httpFormActionCount > 0) {
    addScore(categoryScores, "INSECURE_FORM_SUBMISSION", 60);
    reasons.push("Sensitive information may be submitted over an insecure HTTP connection.");
  }

  if ((dataLeak.passwordHttpForm || dataLeak.otpOrPaymentHttpForm) && (signals.hasPasswordField || signals.hasOTP)) {
    addScore(categoryScores, "INSECURE_FORM_SUBMISSION", 80);
    reasons.push("Password or OTP form action uses insecure HTTP.");
  }

  if (!signals.isTrustedDomain && dataLeak.hiddenIframeCount > 0 && signals.hasPasswordField) {
    addScore(categoryScores, "DATA_EXFILTRATION", 45);
    reasons.push("Hidden iframe appears on a page that also contains a password form.");
  }

  if (!signals.isTrustedDomain && network.thirdPartyXHRRequests >= 3 && network.requestsAfterFormSubmit >= 3) {
    addScore(categoryScores, "DATA_EXFILTRATION", 40);
    reasons.push("This page contacted multiple third-party endpoints after a form interaction.");
  }

  if (!signals.isTrustedDomain && network.requestsAfterPasswordFocus >= 3) {
    addScore(categoryScores, "DATA_EXFILTRATION", 35);
    reasons.push("Multiple third-party requests occurred after a password field interaction.");
  }

  if (dataLeak.thirdPartyApkLinks.length > 0) {
    addScore(categoryScores, "MALICIOUS_APK", 35);
    reasons.push("APK download is served from an unrelated or insecure domain.");
  }

  if (dataLeak.httpApkLinks.length > 0) {
    addScore(categoryScores, "MALICIOUS_APK", 50);
    reasons.push("APK download is served over insecure HTTP.");
  }

  if (!signals.isTrustedDomain && dataLeak.externalScriptCount > 0 && (signals.hasPasswordField || signals.hasOTP)) {
    addScore(categoryScores, "DATA_EXFILTRATION", 25);
    reasons.push("External scripts appear on a page that collects password or OTP metadata.");
  }

  if (!signals.isTrustedDomain && dataLeak.redirectAwayLinkCount >= 10 && dataLeak.thirdPartyIframeCount > 0) {
    addScore(categoryScores, "REDIRECT_SCAM", 30);
    reasons.push("Suspicious redirect pattern to unrelated domains detected.");
  }

  if (!signals.isTrustedDomain && signals.foundGamblingKeywords.length > 0) {
    addScore(categoryScores, "GAMBLING", 25);
    reasons.push(`Gambling keywords detected: ${signals.foundGamblingKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.domainCategorySignals.gambling.length > 0) {
    addScore(categoryScores, "GAMBLING", 25);
    reasons.push(`Gambling-style domain pattern detected: ${signals.domainCategorySignals.gambling.slice(0, 3).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.foundAdultKeywords.length > 0) {
    addScore(categoryScores, "ADULT_CONTENT", 20);
    reasons.push(`Adult content keywords detected: ${signals.foundAdultKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.domainCategorySignals.adult.length > 0) {
    addScore(categoryScores, "ADULT_CONTENT", 20);
    reasons.push(`Adult-content domain pattern detected: ${signals.domainCategorySignals.adult.slice(0, 3).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.foundInvestmentKeywords.length > 0) {
    addScore(categoryScores, "INVESTMENT_SCAM", 30);
    reasons.push(`Investment or crypto scam keywords detected: ${signals.foundInvestmentKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.foundTechSupportKeywords.length > 0) {
    addScore(categoryScores, "TECH_SUPPORT_SCAM", 30);
    reasons.push(`Tech support scam keywords detected: ${signals.foundTechSupportKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.foundFakeShoppingKeywords.length > 0) {
    addScore(categoryScores, "FAKE_SHOPPING", 20);
    reasons.push(`Fake shopping keywords detected: ${signals.foundFakeShoppingKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.foundPrizeKeywords.length > 0) {
    addScore(categoryScores, "PRIZE_SCAM", 20);
    reasons.push(`Prize or giveaway scam keywords detected: ${signals.foundPrizeKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && signals.foundPiratedKeywords.length > 0) {
    addScore(categoryScores, "PIRATED_SOFTWARE", 30);
    reasons.push(`Pirated software keywords detected: ${signals.foundPiratedKeywords.slice(0, 5).join(", ")}.`);
  }

  if (!signals.isTrustedDomain && (signals.hasAdHeavySignal || signals.foundPopupAbuseKeywords.length > 0)) {
    addScore(categoryScores, "MALVERTISING", signals.hasAdHeavySignal ? 35 : 25);
    reasons.push(...signals.adHeavySignals.slice(0, 4));
    if (signals.foundPopupAbuseKeywords.length > 0) {
      reasons.push(`Popup abuse keywords detected: ${signals.foundPopupAbuseKeywords.slice(0, 5).join(", ")}.`);
    }
  }

  let finalScore = Math.min(100, sumScores(categoryScores));
  let category = overrideDominantCategory(signals, dominantCategory(categoryScores));

  if (isContentRiskCategory(category) && !hasContentRiskEscalator(signals)) {
    finalScore = Math.max(CONTENT_RISK_MIN_SCORE, Math.min(finalScore, 55));
    category = "CONTENT_RISK";
    reasons.push("Content-risk page capped below HIGH_RISK because no credential, APK, OTP, or aggressive scam behavior was found.");
  }

  if (!configuredCategoryIds.has(category) && category !== "SAFE") {
    reasons.push(`Category ${category} is rule-defined and not present in risky_categories.json.`);
  }

  if (signals.isTrustedDomain && !strongDanger) {
    finalScore = Math.min(finalScore, 20);
    category = "SAFE";
    reasons.push("Trusted official domain capped at low risk because no strong danger signal was found.");
  }

  if (isFinanceOrNewsSafeContext(signals) && !strongDanger) {
    finalScore = Math.min(finalScore, 20);
    reasons.push("Finance/news context reduced because banking/account words alone are not enough.");
  }

  return buildRisk(finalScore, levelFromScore(finalScore), category || "SAFE", unique(reasons), "LOCAL_MODEL");
}

function buildRisk(score, level, category, reasons, source) {
  const riskScore = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));

  return {
    score: riskScore,
    riskScore,
    level: level || levelFromScore(riskScore),
    category: category || "UNKNOWN",
    reasons: reasons.length ? reasons : ["No high-risk indicators were detected."],
    shouldWarn: false,
    source: source || "LOCAL_MODEL"
  };
}

function shouldShowWarning(risk, signals, settings) {
  if (risk.score < settings.warningThreshold) {
    return false;
  }

  if (risk.level === "HIGH_RISK") {
    return true;
  }

  return risk.level === "SUSPICIOUS" && !signals.isTrustedDomain;
}

async function saveScanResult(scanResult) {
  const current = await chrome.storage.local.get(["argusTabScans"]);
  const argusTabScans = current.argusTabScans || {};

  if (scanResult.tabId) {
    argusTabScans[String(scanResult.tabId)] = scanResult;
  }

  await chrome.storage.local.set({
    lastArgusScan: scanResult,
    argusTabScans
  });
}

async function getLatestScan(tabId) {
  const stored = await chrome.storage.local.get(["lastArgusScan", "argusTabScans"]);
  const tabScans = stored.argusTabScans || {};

  if (tabId && tabScans[String(tabId)]) {
    return tabScans[String(tabId)];
  }

  return stored.lastArgusScan || null;
}

async function clearLastScan(tabId) {
  const stored = await chrome.storage.local.get(["argusTabScans"]);
  const tabScans = stored.argusTabScans || {};

  if (tabId && tabScans[String(tabId)]) {
    delete tabScans[String(tabId)];
  }

  await chrome.storage.local.set({ argusTabScans: tabScans });
  await chrome.storage.local.remove(["lastArgusScan"]);
}

async function saveFalsePositiveReport(payload) {
  const stored = await chrome.storage.local.get(["falsePositiveReports"]);
  const reports = stored.falsePositiveReports || [];
  reports.push(sanitizeFalsePositiveReport(payload));
  await chrome.storage.local.set({
    falsePositiveReports: reports.slice(-100)
  });
}

function sanitizeFalsePositiveReport(payload) {
  const raw = payload && typeof payload === "object" ? payload : {};
  const risk = raw.risk && typeof raw.risk === "object" ? raw.risk : raw;

  return {
    domain: String(raw.domain || "").slice(0, 180),
    score: Math.max(0, Math.min(100, Math.round(Number(risk.score ?? risk.riskScore) || 0))),
    level: String(risk.level || "UNKNOWN").slice(0, 40),
    category: String(risk.category || "UNKNOWN").slice(0, 80),
    reasons: toArray(risk.reasons).slice(0, 8).map((reason) => String(reason).slice(0, 240)),
    timestamp: String(raw.timestamp || new Date().toISOString())
  };
}

function toArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function addLimited(list, value, limit) {
  if (!value || list.includes(value)) {
    return;
  }

  list.push(value);
  if (list.length > limit) {
    list.shift();
  }
}

function addScore(categoryScores, category, amount) {
  categoryScores[category] = (categoryScores[category] || 0) + amount;
}

function sumScores(categoryScores) {
  return Object.values(categoryScores).reduce((total, value) => total + value, 0);
}

function dominantCategory(categoryScores) {
  return Object.entries(categoryScores).sort((a, b) => b[1] - a[1])[0]?.[0] || "SAFE";
}

function overrideDominantCategory(signals, currentCategory) {
  const dataLeak = signals.dataLeakSignals || normalizeDataLeakSignals({});
  const network = signals.networkSignals || normalizeNetworkSignals({});

  if (dataLeak.passwordHttpForm || dataLeak.otpOrPaymentHttpForm || dataLeak.httpFormActionCount > 0) {
    return "INSECURE_FORM_SUBMISSION";
  }

  if (
    dataLeak.passwordCrossDomainForm ||
    dataLeak.otpOrPaymentCrossDomainForm ||
    dataLeak.crossDomainFormActionCount > 0 ||
    network.requestsAfterFormSubmit >= 3 ||
    network.requestsAfterPasswordFocus >= 3
  ) {
    return "DATA_EXFILTRATION";
  }

  if (signals.foundBankingKeywords.length > 0 && (signals.hasPasswordField || signals.hasOTP)) {
    return "FAKE_BANKING";
  }

  if (signals.foundStoreKeywords.length > 0 && signals.apkLinks.length > 0) {
    return "FAKE_APP_STORE";
  }

  if (signals.apkLinks.length > 0) {
    return "MALICIOUS_APK";
  }

  if (signals.foundGamblingKeywords.length > 0 || signals.domainCategorySignals.gambling.length > 0) {
    return "GAMBLING";
  }

  if (signals.foundAdultKeywords.length > 0 || signals.domainCategorySignals.adult.length > 0) {
    return "ADULT_CONTENT";
  }

  return currentCategory || "SAFE";
}

function levelFromScore(score) {
  if (score >= 70) {
    return "HIGH_RISK";
  }
  if (score >= 35) {
    return "SUSPICIOUS";
  }
  return "SAFE";
}

function isContentRiskCategory(category) {
  return category === "CONTENT_RISK" || category === "GAMBLING" || category === "ADULT_CONTENT";
}

function hasContentRiskEscalator(signals) {
  const dataLeak = signals.dataLeakSignals || normalizeDataLeakSignals({});
  const network = signals.networkSignals || normalizeNetworkSignals({});
  return (
    signals.apkLinks.length > 0 ||
    signals.hasPasswordField ||
    signals.hasOTP ||
    signals.foundPopupAbuseKeywords.length > 0 ||
    dataLeak.crossDomainFormActionCount > 0 ||
    dataLeak.httpFormActionCount > 0 ||
    dataLeak.hiddenIframeCount > 0 ||
    dataLeak.thirdPartyApkLinks.length > 0 ||
    dataLeak.httpApkLinks.length > 0 ||
    network.requestsAfterFormSubmit >= 3 ||
    network.requestsAfterPasswordFocus >= 3
  );
}

function hasStrongDangerSignals(signals) {
  const dataLeak = signals.dataLeakSignals || normalizeDataLeakSignals({});
  const network = signals.networkSignals || normalizeNetworkSignals({});
  return (
    signals.apkLinks.length > 0 ||
    signals.hasPasswordField ||
    signals.hasOTP ||
    (signals.foundStoreKeywords.length > 0 && signals.apkLinks.length > 0) ||
    (signals.foundBankingKeywords.length > 0 && (signals.hasPasswordField || signals.hasOTP)) ||
    (signals.hasAdHeavySignal && (signals.foundPopupAbuseKeywords.length > 0 || signals.foundGamblingKeywords.length > 0)) ||
    dataLeak.passwordCrossDomainForm ||
    dataLeak.otpOrPaymentCrossDomainForm ||
    dataLeak.passwordHttpForm ||
    dataLeak.otpOrPaymentHttpForm ||
    dataLeak.httpApkLinks.length > 0 ||
    dataLeak.thirdPartyApkLinks.length > 0 ||
    network.requestsAfterFormSubmit >= 3 ||
    network.requestsAfterPasswordFocus >= 3
  );
}

function hasObviousHighRiskEvidence(signals) {
  const dataLeak = signals.dataLeakSignals || normalizeDataLeakSignals({});
  return (
    (signals.apkLinks.length > 0 && signals.foundStoreKeywords.length > 0) ||
    (signals.hasPasswordField && signals.hasOTP) ||
    (signals.foundBankingKeywords.length > 0 && signals.hasPasswordField && signals.hasOTP) ||
    dataLeak.passwordCrossDomainForm ||
    dataLeak.otpOrPaymentCrossDomainForm ||
    dataLeak.passwordHttpForm ||
    dataLeak.otpOrPaymentHttpForm ||
    dataLeak.httpApkLinks.length > 0
  );
}

function isFinanceOrNewsSafeContext(signals) {
  return signals.isTrustedDomain && (
    signals.domain.includes("finance.yahoo.com") ||
    signals.domain.endsWith("set.or.th") ||
    signals.domain.endsWith("sec.or.th") ||
    signals.domain.endsWith("bot.or.th")
  );
}

function isOfficialAppStore(domain) {
  return [
    "play.google.com",
    "apps.apple.com",
    "galaxystore.samsung.com",
    "apps.samsung.com"
  ].some((official) => isDomainMatch(domain, official));
}

function isDomainMatch(domain, expectedDomain) {
  return domain === expectedDomain || domain.endsWith(`.${expectedDomain}`);
}

function parseUrlMetadata(value) {
  try {
    const parsed = new URL(value);
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

function getInitiatorDomain(value) {
  return parseUrlMetadata(value).hostname;
}

function isSuspiciousRequestType(type) {
  return ["script", "sub_frame", "object", "xmlhttprequest", "fetch", "beacon", "ping"].includes(type);
}

function isSearchEnginePage(url, domain, pathname) {
  const searchDomains = ["google.com", "www.google.com", "google.co.th", "www.google.co.th", "bing.com", "www.bing.com", "search.brave.com", "duckduckgo.com", "www.duckduckgo.com"];

  if (!searchDomains.some((candidate) => isDomainMatch(domain, candidate)) && !isGoogleDomain(domain)) {
    return false;
  }

  if (isGoogleDomain(domain) || domain.includes("bing.") || domain === "search.brave.com") {
    return pathname === "/search";
  }

  return domain.includes("duckduckgo.com") && (pathname === "/" || pathname === "/html" || pathname === "/lite");
}

function getSuspiciousDomainSignals(domain) {
  const suspiciousWords = ["verify", "secure", "update", "login", "account", "wallet", "bank"];
  return suspiciousWords
    .filter((word) => domain.includes(word))
    .map((word) => `Domain contains suspicious word: ${word}.`);
}

function getDomainCategorySignals(domain) {
  return {
    gambling: GAMBLING_DOMAIN_PATTERNS.filter((pattern) => domain.includes(pattern)),
    adult: ADULT_DOMAIN_PATTERNS.filter((pattern) => domain.includes(pattern))
  };
}

function isGoogleDomain(domain) {
  return /^(.+\.)?google\.[a-z.]+$/i.test(domain);
}

function hasBrandImpersonationPattern(domain) {
  return /(g00gle|faceb00k|paypa[l1i]|micros0ft|samsunng|app1e)/i.test(domain);
}
