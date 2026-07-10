try {
  importScripts("engine/argus_engine.js");
} catch (error) {
  console.error("[Project Argus] modular engine failed to load; legacy detector will be used.", error);
}

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
const TEMPORAL_WINDOW_MS = 30000;
const SENSITIVE_REQUEST_WINDOW_MS = 15000;
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const MULTI_LABEL_SUFFIXES = new Set([
  "co.th", "or.th", "go.th", "ac.th", "in.th",
  "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au",
  "co.jp", "co.kr", "com.sg", "com.my", "co.nz",
  "github.io", "pages.dev", "vercel.app", "netlify.app", "appspot.com", "cloudfront.net"
]);

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
let detectionPolicyCache = null;
const tabNetworkSignals = new Map();
const tabPageDomains = new Map();
const tabRescanTimers = new Map();

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
      const timer = tabRescanTimers.get(tabId);
      if (timer) clearTimeout(timer);
      tabRescanTimers.delete(tabId);
    });
  }

  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
      if (changeInfo.status === "loading") {
        preserveOrClearTemporalState(tabId);
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
  const isThirdParty = referenceDomain ? !isSameSiteDomain(requestMeta.hostname, referenceDomain) : false;
  const signals = getNetworkSignals(details.tabId);
  const now = Date.now();
  const method = String(details.method || "GET").toUpperCase();
  const isWriteRequest = WRITE_METHODS.has(method);
  const afterFormSubmit = Boolean(signals.lastFormSubmitAt && now - signals.lastFormSubmitAt < SENSITIVE_REQUEST_WINDOW_MS);
  const afterSensitiveFocus = Boolean(signals.lastPasswordFocusAt && now - signals.lastPasswordFocusAt < SENSITIVE_REQUEST_WINDOW_MS);
  const followsSensitiveInteraction = (afterFormSubmit && signals.lastFormWasSensitive) || afterSensitiveFocus;

  signals.totalRequests += 1;
  if (isThirdParty) {
    signals.thirdPartyRequests += 1;
  }
  if (requestMeta.protocol === "http:") {
    signals.insecureHttpRequests += 1;
  }
  if (isWriteRequest) {
    signals.writeRequests += 1;
    if (isThirdParty) signals.thirdPartyWriteRequests += 1;
    if (requestMeta.protocol === "http:") signals.insecureWriteRequests += 1;
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
  if (afterFormSubmit && isThirdParty) {
    signals.requestsAfterFormSubmit += 1;
    addTimelineEvent(signals, "THIRD_PARTY_AFTER_FORM", now);
  }
  if (afterSensitiveFocus && isThirdParty) {
    signals.requestsAfterPasswordFocus += 1;
    addTimelineEvent(signals, "THIRD_PARTY_AFTER_PASSWORD", now);
  }
  if (afterFormSubmit && isWriteRequest) {
    signals.writeRequestsAfterFormSubmit += 1;
    if (requestMeta.protocol === "http:") signals.insecureWriteRequestsAfterFormSubmit += 1;
    if (isThirdParty) signals.thirdPartyWriteRequestsAfterFormSubmit += 1;
    addTimelineEvent(signals, "WRITE_AFTER_FORM", now);

    if (signals.lastFormWasSensitive) {
      signals.sensitiveWriteRequestsAfterFormSubmit += 1;
      if (requestMeta.protocol === "http:") {
        signals.insecureSensitiveWriteRequests += 1;
        addTimelineEvent(signals, "UNENCRYPTED_SENSITIVE_WRITE", now);
      }
      if (isThirdParty) {
        signals.crossDomainSensitiveWriteRequests += 1;
        addTimelineEvent(signals, "CROSS_DOMAIN_SENSITIVE_WRITE", now);
      }
    }
  }
  if (["beacon", "ping"].includes(details.type) && followsSensitiveInteraction) {
    signals.beaconOrPingAfterSensitiveInput += 1;
    addTimelineEvent(signals, "BEACON_AFTER_SENSITIVE_INPUT", now);
  }
  if (details.type === "image" && method === "GET" && requestMeta.hasQuery && isThirdParty &&
    afterFormSubmit && signals.lastFormWasSensitive) {
    signals.queryBearingGetAfterSensitiveForm += 1;
    addTimelineEvent(signals, "QUERY_GET_AFTER_SENSITIVE_FORM", now);
  }
  if (signals.lastFormSubmitAt && now - signals.lastFormSubmitAt < TEMPORAL_WINDOW_MS && isThirdParty && details.type === "main_frame") {
    signals.formSubmitThenCrossDomainRedirectCount += 1;
    addTimelineEvent(signals, "CROSS_DOMAIN_REDIRECT_AFTER_FORM", now);
  }
  if (isThirdParty && isSuspiciousRequestType(details.type)) {
    addLimited(signals.suspiciousRequestDomains, requestMeta.hostname, 30);
  }

  signals.updatedAt = now;
  tabNetworkSignals.set(details.tabId, signals);

  if ((afterFormSubmit && isWriteRequest) ||
    (["beacon", "ping"].includes(details.type) && followsSensitiveInteraction) ||
    (details.type === "image" && method === "GET" && requestMeta.hasQuery && isThirdParty && afterFormSubmit && signals.lastFormWasSensitive)) {
    schedulePageRescan(details.tabId, 300);
  }
}

function recordPageEvent(type, payload, sender) {
  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (!Number.isInteger(tabId) || tabId < 0) {
    return;
  }

  const signals = getNetworkSignals(tabId);
  const now = Date.now();
  if (type === PASSWORD_FOCUS_MESSAGE) {
    signals.lastPasswordFocusAt = now;
    signals.lastSensitiveKind = String(payload && payload.sensitiveKind || "sensitive").slice(0, 40);
    addTimelineEvent(signals, "PASSWORD_FOCUS", now);
  }
  if (type === FORM_SUBMITTED_MESSAGE) {
    signals.lastFormSubmitAt = now;
    signals.lastFormWasSensitive = Boolean(payload && payload.hasSensitiveFields);
    signals.lastFormActionProtocol = String(payload && payload.actionProtocol || "").slice(0, 12);
    signals.lastFormCrossDomain = Boolean(payload && payload.isCrossDomainAction);
    signals.lastFormMethod = String(payload && payload.formMethod || "GET").slice(0, 12);
    addTimelineEvent(signals, "FORM_SUBMIT", now);
    if (signals.lastFormWasSensitive) addTimelineEvent(signals, "SENSITIVE_FORM_SUBMIT", now);
  }
  if (type === DOWNLOAD_CLICKED_MESSAGE) {
    signals.downloadClickCount += 1;
    if (signals.lastFormSubmitAt && now - signals.lastFormSubmitAt < TEMPORAL_WINDOW_MS) {
      signals.downloadAfterFormSubmitCount += 1;
    }
    addTimelineEvent(signals, "DOWNLOAD_CLICK", now);
  }
  signals.updatedAt = now;
  tabNetworkSignals.set(tabId, signals);
  schedulePageRescan(tabId, type === FORM_SUBMITTED_MESSAGE ? 700 : 350);
}

function schedulePageRescan(tabId, delayMs) {
  const existing = tabRescanTimers.get(tabId);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(() => {
    tabRescanTimers.delete(tabId);
    chrome.tabs.sendMessage(tabId, { type: RESCAN_MESSAGE }, () => {
      chrome.runtime.lastError;
    });
  }, Math.max(100, Number(delayMs) || 300));

  tabRescanTimers.set(tabId, timer);
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
    writeRequests: 0,
    thirdPartyWriteRequests: 0,
    insecureWriteRequests: 0,
    suspiciousRequestDomains: [],
    requestsAfterFormSubmit: 0,
    requestsAfterPasswordFocus: 0,
    writeRequestsAfterFormSubmit: 0,
    insecureWriteRequestsAfterFormSubmit: 0,
    thirdPartyWriteRequestsAfterFormSubmit: 0,
    sensitiveWriteRequestsAfterFormSubmit: 0,
    insecureSensitiveWriteRequests: 0,
    crossDomainSensitiveWriteRequests: 0,
    beaconOrPingAfterSensitiveInput: 0,
    queryBearingGetAfterSensitiveForm: 0,
    downloadClickCount: 0,
    formSubmitThenCrossDomainRedirectCount: 0,
    downloadAfterFormSubmitCount: 0,
    recentEvents: [],
    lastFormSubmitAt: 0,
    lastPasswordFocusAt: 0,
    lastFormWasSensitive: false,
    lastFormActionProtocol: "",
    lastFormCrossDomain: false,
    lastFormMethod: "GET",
    lastSensitiveKind: "",
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
    writeRequests: signals.writeRequests,
    thirdPartyWriteRequests: signals.thirdPartyWriteRequests,
    insecureWriteRequests: signals.insecureWriteRequests,
    requestsAfterFormSubmit: signals.requestsAfterFormSubmit,
    requestsAfterPasswordFocus: signals.requestsAfterPasswordFocus,
    writeRequestsAfterFormSubmit: signals.writeRequestsAfterFormSubmit,
    insecureWriteRequestsAfterFormSubmit: signals.insecureWriteRequestsAfterFormSubmit,
    thirdPartyWriteRequestsAfterFormSubmit: signals.thirdPartyWriteRequestsAfterFormSubmit,
    sensitiveWriteRequestsAfterFormSubmit: signals.sensitiveWriteRequestsAfterFormSubmit,
    insecureSensitiveWriteRequests: signals.insecureSensitiveWriteRequests,
    crossDomainSensitiveWriteRequests: signals.crossDomainSensitiveWriteRequests,
    beaconOrPingAfterSensitiveInput: signals.beaconOrPingAfterSensitiveInput,
    queryBearingGetAfterSensitiveForm: signals.queryBearingGetAfterSensitiveForm,
    suspiciousRequestDomains: signals.suspiciousRequestDomains.slice(0, 30),
    temporalSignals: {
      formSubmitThenThirdPartyCount: signals.requestsAfterFormSubmit,
      passwordFocusThenThirdPartyCount: signals.requestsAfterPasswordFocus,
      formSubmitThenCrossDomainRedirectCount: signals.formSubmitThenCrossDomainRedirectCount,
      downloadAfterFormSubmitCount: signals.downloadAfterFormSubmitCount,
      unencryptedSensitiveWriteCount: signals.insecureSensitiveWriteRequests,
      crossDomainSensitiveWriteCount: signals.crossDomainSensitiveWriteRequests,
      beaconAfterSensitiveInputCount: signals.beaconOrPingAfterSensitiveInput,
      recentEventTypes: signals.recentEvents
        .filter((event) => Date.now() - event.at <= TEMPORAL_WINDOW_MS)
        .map((event) => event.type)
        .slice(-20)
    }
  };
}

function addTimelineEvent(signals, type, at) {
  signals.recentEvents = Array.isArray(signals.recentEvents) ? signals.recentEvents : [];
  signals.recentEvents.push({ type, at });
  signals.recentEvents = signals.recentEvents
    .filter((event) => at - event.at <= TEMPORAL_WINDOW_MS)
    .slice(-40);
}

function preserveOrClearTemporalState(tabId) {
  const signals = tabNetworkSignals.get(tabId);
  const now = Date.now();
  if (!signals || (!signals.lastFormSubmitAt && !signals.lastPasswordFocusAt)) {
    tabNetworkSignals.delete(tabId);
    return;
  }

  const lastInteraction = Math.max(signals.lastFormSubmitAt || 0, signals.lastPasswordFocusAt || 0);
  if (now - lastInteraction > TEMPORAL_WINDOW_MS) {
    tabNetworkSignals.delete(tabId);
    return;
  }

  signals.totalRequests = 0;
  signals.thirdPartyRequests = 0;
  signals.thirdPartyScriptRequests = 0;
  signals.thirdPartyFrameRequests = 0;
  signals.thirdPartyXHRRequests = 0;
  signals.insecureHttpRequests = 0;
  signals.writeRequests = 0;
  signals.thirdPartyWriteRequests = 0;
  signals.insecureWriteRequests = 0;
  signals.suspiciousRequestDomains = [];
  signals.updatedAt = now;
  tabNetworkSignals.set(tabId, signals);
}

async function handlePageScan(pageData, sender) {
  const tabId = sender && sender.tab ? sender.tab.id : null;
  const settings = await loadSettings();
  const trustedDomains = await loadTrustedDomains();
  const riskyCategories = await loadRiskyCategories();
  const detectionPolicy = await loadDetectionPolicy();
  const signals = normalizeSignals(pageData, trustedDomains);
  if (Number.isInteger(tabId) && tabId >= 0) {
    tabPageDomains.set(tabId, signals.domain);
    signals.networkSignals = exportNetworkSignals(tabId);
  }
  const ruleRisk = calculateRuleRisk(signals, riskyCategories, detectionPolicy);
  const modelStatus = {
    mode: "LOCAL_MODEL",
    externalAi: false,
    engine: "ARGUS_EVIDENCE_ENGINE",
    policyVersion: detectionPolicy.version || "3.0.0",
    message: "Project Argus data-flow priority engine active."
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
    timestamp: new Date().toISOString(),
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
      confidence: finalRisk.confidence,
      policyVersion: finalRisk.policyVersion,
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

  if (Number.isInteger(tabId) && tabId >= 0 && shouldWarn) {
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

async function loadDetectionPolicy() {
  if (detectionPolicyCache) {
    return detectionPolicyCache;
  }

  const fallbackPolicy = typeof ArgusEngine !== "undefined" ? ArgusEngine.DEFAULT_POLICY : {};
  detectionPolicyCache = await fetchJson("engine/detection_policy.json", fallbackPolicy);
  return detectionPolicyCache;
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
    pageProtocol: String(pageData.pageProtocol || parseUrlMetadata(url).protocol || ""),
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
    sensitiveFormCount: Number(raw.sensitiveFormCount) || 0,
    formActionUrls: toArray(raw.formActionUrls).slice(0, 30),
    emptyFormActionCount: Number(raw.emptyFormActionCount) || 0,
    httpFormActionCount: Number(raw.httpFormActionCount) || 0,
    crossDomainFormActionCount: Number(raw.crossDomainFormActionCount) || 0,
    passwordCrossDomainForm: Boolean(raw.passwordCrossDomainForm),
    otpOrPaymentCrossDomainForm: Boolean(raw.otpOrPaymentCrossDomainForm),
    passwordHttpForm: Boolean(raw.passwordHttpForm),
    otpOrPaymentHttpForm: Boolean(raw.otpOrPaymentHttpForm),
    sameOriginSensitiveHttpForm: Boolean(raw.sameOriginSensitiveHttpForm),
    httpPageWithSensitiveForm: Boolean(raw.httpPageWithSensitiveForm),
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
    redirectAwayDomains: toArray(raw.redirectAwayDomains).slice(0, 20),
    inlineScriptCount: Number(raw.inlineScriptCount) || 0,
    scriptNetworkSinkCount: Number(raw.scriptNetworkSinkCount) || 0,
    dynamicEndpointAssemblyCount: Number(raw.dynamicEndpointAssemblyCount) || 0,
    externalUrlHints: toArray(raw.externalUrlHints).slice(0, 20),
    delayedRelayIndicator: Boolean(raw.delayedRelayIndicator),
    popupMessageTrapIndicator: Boolean(raw.popupMessageTrapIndicator),
    clipboardReadIndicator: Boolean(raw.clipboardReadIndicator),
    fileMetadataHarvestIndicator: Boolean(raw.fileMetadataHarvestIndicator),
    guardedNetworkToggleIndicator: Boolean(raw.guardedNetworkToggleIndicator),
    preventedSubmitIndicator: Boolean(raw.preventedSubmitIndicator),
    localFormWithJsSinkIndicator: Boolean(raw.localFormWithJsSinkIndicator),
    credentialLikeTextFieldCount: Number(raw.credentialLikeTextFieldCount) || 0,
    sensitiveTextareaCount: Number(raw.sensitiveTextareaCount) || 0,
    deceptiveLowFrictionContent: Boolean(raw.deceptiveLowFrictionContent)
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
    writeRequests: Number(raw.writeRequests) || 0,
    thirdPartyWriteRequests: Number(raw.thirdPartyWriteRequests) || 0,
    insecureWriteRequests: Number(raw.insecureWriteRequests) || 0,
    requestsAfterFormSubmit: Number(raw.requestsAfterFormSubmit) || 0,
    requestsAfterPasswordFocus: Number(raw.requestsAfterPasswordFocus) || 0,
    writeRequestsAfterFormSubmit: Number(raw.writeRequestsAfterFormSubmit) || 0,
    insecureWriteRequestsAfterFormSubmit: Number(raw.insecureWriteRequestsAfterFormSubmit) || 0,
    thirdPartyWriteRequestsAfterFormSubmit: Number(raw.thirdPartyWriteRequestsAfterFormSubmit) || 0,
    sensitiveWriteRequestsAfterFormSubmit: Number(raw.sensitiveWriteRequestsAfterFormSubmit) || 0,
    insecureSensitiveWriteRequests: Number(raw.insecureSensitiveWriteRequests) || 0,
    crossDomainSensitiveWriteRequests: Number(raw.crossDomainSensitiveWriteRequests) || 0,
    beaconOrPingAfterSensitiveInput: Number(raw.beaconOrPingAfterSensitiveInput) || 0,
    queryBearingGetAfterSensitiveForm: Number(raw.queryBearingGetAfterSensitiveForm) || 0,
    suspiciousRequestDomains: toArray(raw.suspiciousRequestDomains).slice(0, 30),
    temporalSignals: normalizeTemporalSignals(raw.temporalSignals)
  };
}

function normalizeTemporalSignals(value) {
  const raw = value && typeof value === "object" ? value : {};
  return {
    formSubmitThenThirdPartyCount: Number(raw.formSubmitThenThirdPartyCount) || 0,
    passwordFocusThenThirdPartyCount: Number(raw.passwordFocusThenThirdPartyCount) || 0,
    formSubmitThenCrossDomainRedirectCount: Number(raw.formSubmitThenCrossDomainRedirectCount) || 0,
    downloadAfterFormSubmitCount: Number(raw.downloadAfterFormSubmitCount) || 0,
    unencryptedSensitiveWriteCount: Number(raw.unencryptedSensitiveWriteCount) || 0,
    crossDomainSensitiveWriteCount: Number(raw.crossDomainSensitiveWriteCount) || 0,
    beaconAfterSensitiveInputCount: Number(raw.beaconAfterSensitiveInputCount) || 0,
    recentEventTypes: toArray(raw.recentEventTypes).slice(-20)
  };
}

function calculateRuleRisk(signals, categoryConfig, detectionPolicy) {
  if (typeof ArgusEngine !== "undefined" && ArgusEngine.evaluate) {
    return ArgusEngine.evaluate(signals, categoryConfig, detectionPolicy);
  }

  console.warn("[Project Argus] modular engine unavailable; using legacy local detector.");
  return calculateLegacyRuleRisk(signals, categoryConfig);
}

function calculateLegacyRuleRisk(signals, categoryConfig) {
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

  if (!signals.isTrustedDomain && dataLeak.credentialLikeTextFieldCount > 0) {
    addScore(categoryScores, "PHISHING_LOGIN", 30);
    reasons.push(`Credential-like text fields detected without normal password input (${dataLeak.credentialLikeTextFieldCount}).`);
  }

  if (!signals.isTrustedDomain && dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.localFormWithJsSinkIndicator) {
    addScore(categoryScores, "DATA_EXFILTRATION", 45);
    reasons.push("Local-looking form is handled by JavaScript network logic while collecting credential-like fields.");
  }

  if (!signals.isTrustedDomain && dataLeak.scriptNetworkSinkCount > 0 && dataLeak.externalUrlHints.length > 0) {
    addScore(categoryScores, "DATA_EXFILTRATION", 35);
    reasons.push("Inline script contains network-send behavior and external endpoint hints.");
  }

  if (!signals.isTrustedDomain && dataLeak.dynamicEndpointAssemblyCount > 0 && dataLeak.scriptNetworkSinkCount > 0) {
    addScore(categoryScores, "DATA_EXFILTRATION", 30);
    reasons.push("JavaScript appears to assemble a network endpoint dynamically before sending metadata.");
  }

  if (!signals.isTrustedDomain && dataLeak.delayedRelayIndicator && dataLeak.localFormWithJsSinkIndicator) {
    addScore(categoryScores, "DATA_EXFILTRATION", 35);
    reasons.push("Form handling includes delayed JavaScript relay behavior.");
  }

  if (!signals.isTrustedDomain && dataLeak.popupMessageTrapIndicator && dataLeak.scriptNetworkSinkCount > 0) {
    addScore(categoryScores, "DATA_EXFILTRATION", 45);
    reasons.push("Popup consent flow can pass messages back into network-send logic.");
  }

  if (!signals.isTrustedDomain && (dataLeak.clipboardReadIndicator || dataLeak.fileMetadataHarvestIndicator)) {
    addScore(categoryScores, "DATA_EXFILTRATION", 35);
    reasons.push("Page script can inspect clipboard or uploaded-file metadata.");
  }

  if (!signals.isTrustedDomain && dataLeak.sensitiveTextareaCount > 0 && (dataLeak.clipboardReadIndicator || dataLeak.scriptNetworkSinkCount > 0)) {
    addScore(categoryScores, "DATA_EXFILTRATION", 40);
    reasons.push("Sensitive recovery-style text area appears with script-based data movement behavior.");
  }

  if (!signals.isTrustedDomain && dataLeak.guardedNetworkToggleIndicator && dataLeak.scriptNetworkSinkCount > 0) {
    addScore(categoryScores, "DATA_EXFILTRATION", 20);
    reasons.push("Script contains guarded network-send behavior that may hide during basic scans.");
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
    (dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.localFormWithJsSinkIndicator) ||
    (dataLeak.scriptNetworkSinkCount > 0 && dataLeak.dynamicEndpointAssemblyCount > 0) ||
    (dataLeak.popupMessageTrapIndicator && dataLeak.scriptNetworkSinkCount > 0) ||
    dataLeak.clipboardReadIndicator ||
    dataLeak.fileMetadataHarvestIndicator ||
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
    (dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.localFormWithJsSinkIndicator) ||
    (dataLeak.scriptNetworkSinkCount > 0 && dataLeak.dynamicEndpointAssemblyCount > 0) ||
    (dataLeak.popupMessageTrapIndicator && dataLeak.scriptNetworkSinkCount > 0) ||
    dataLeak.clipboardReadIndicator ||
    dataLeak.fileMetadataHarvestIndicator ||
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
    dataLeak.httpApkLinks.length > 0 ||
    (dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.localFormWithJsSinkIndicator) ||
    (dataLeak.scriptNetworkSinkCount > 0 && dataLeak.dynamicEndpointAssemblyCount > 0) ||
    (dataLeak.popupMessageTrapIndicator && dataLeak.scriptNetworkSinkCount > 0) ||
    (dataLeak.sensitiveTextareaCount > 0 && (dataLeak.clipboardReadIndicator || dataLeak.scriptNetworkSinkCount > 0))
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

function isSameSiteDomain(domain, otherDomain) {
  if (!domain || !otherDomain) return false;
  if (domain === otherDomain || domain.endsWith(`.${otherDomain}`) || otherDomain.endsWith(`.${domain}`)) return true;
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

function parseUrlMetadata(value) {
  try {
    const parsed = new URL(value);
    return {
      protocol: parsed.protocol,
      hostname: parsed.hostname.toLowerCase(),
      pathname: parsed.pathname || "/",
      hasQuery: parsed.search.length > 1,
      sanitizedUrl: `${parsed.origin}${parsed.pathname}`
    };
  } catch (error) {
    return {
      protocol: "",
      hostname: "",
      pathname: "",
      hasQuery: false,
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
