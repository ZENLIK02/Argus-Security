let engineReady = false;
try {
  importScripts("engine/shared_lists.js", "engine/domain_similarity.js", "engine/brand_identity.js", "engine/feature_extractor.js", "engine/trained_model.js", "engine/argus_engine.js", "engine/evidence_decision_policy.js", "engine/navigation_session_guard.js", "engine/network_correlation.js", "engine/scan_freshness.js", "engine/feedback_endpoint.js", "engine/reputation.js", "engine/reputation_client.js");
  engineReady = typeof ArgusEngine !== "undefined" && typeof ArgusEvidencePolicy !== "undefined" &&
    typeof ArgusNavigationGuard !== "undefined" && typeof ArgusNetworkCorrelation !== "undefined" &&
    typeof ArgusScanFreshness !== "undefined" && typeof ArgusSharedLists !== "undefined" &&
    typeof ArgusDomainSimilarity !== "undefined" && typeof ArgusReputation !== "undefined" &&
    typeof ArgusReputationClient !== "undefined" && typeof ArgusFeatureExtractor !== "undefined" &&
    typeof ArgusBrandIdentity !== "undefined";
} catch (error) {
  console.error("[Project Argus] modular engine failed to load; scanning is disabled until the extension is reloaded.", error);
}
if (!engineReady) {
  console.error("[Project Argus] required engine modules are unavailable; Project Argus will report ENGINE_UNAVAILABLE instead of scanning. There is no silent legacy fallback.");
}

const SCAN_MESSAGE = "ARGUS_PAGE_SCAN";
const GET_LATEST_MESSAGE = "ARGUS_GET_LATEST_SCAN";
const RESCAN_MESSAGE = "ARGUS_RESCAN_PAGE";
const REPORT_FALSE_POSITIVE_MESSAGE = "ARGUS_REPORT_FALSE_POSITIVE";
const CLEAR_LAST_SCAN_MESSAGE = "ARGUS_CLEAR_LAST_SCAN";
const PASSWORD_FOCUS_MESSAGE = "ARGUS_PASSWORD_FIELD_FOCUSED";
const FORM_SUBMITTED_MESSAGE = "ARGUS_FORM_SUBMITTED";
const DOWNLOAD_CLICKED_MESSAGE = "ARGUS_DOWNLOAD_CLICKED";
const PAGE_CHANGED_MESSAGE = "ARGUS_PAGE_CHANGED";
const SETTINGS_KEY = "argusSettings";
const MODEL_VERSION = "5.0.0";
// The evidence decision policy is the single authority for status/level/score/
// warning. Source its version + report schema from that module so there is one
// definition (falls back only if the engine failed to load — see engineReady).
const POLICY_VERSION = (typeof ArgusEvidencePolicy !== "undefined" && ArgusEvidencePolicy.POLICY_VERSION) || "evidence-first-v2";
const REPORT_SCHEMA_VERSION = (typeof ArgusEvidencePolicy !== "undefined" && ArgusEvidencePolicy.REPORT_SCHEMA_VERSION) || "2";
const TEMPORAL_WINDOW_MS = 30000;
const SENSITIVE_REQUEST_WINDOW_MS = 15000;
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
// Domain/category lists come from the shared ArgusSharedLists module (single source
// of truth with content.js — F8). Guarded so the worker still loads in degraded
// mode (engine load failure) and can return ENGINE_UNAVAILABLE instead of dying.
const SHARED_LISTS = typeof ArgusSharedLists !== "undefined" ? ArgusSharedLists : {};
const KNOWN_IDENTITY_DOMAINS = SHARED_LISTS.KNOWN_IDENTITY_DOMAINS || [];
const KNOWN_PAYMENT_DOMAINS = SHARED_LISTS.KNOWN_PAYMENT_DOMAINS || [];
const KNOWN_ANALYTICS_DOMAINS = SHARED_LISTS.KNOWN_ANALYTICS_DOMAINS || [];
const KNOWN_AD_DOMAINS = SHARED_LISTS.KNOWN_AD_DOMAINS || [];
const CDN_DOMAIN_HINTS = SHARED_LISTS.CDN_DOMAIN_HINTS || [];
const MULTI_LABEL_SUFFIXES = new Set(SHARED_LISTS.MULTI_LABEL_SUFFIXES || []);
const GAMBLING_DOMAIN_PATTERNS = SHARED_LISTS.GAMBLING_DOMAIN_PATTERNS || [];
const ADULT_DOMAIN_PATTERNS = SHARED_LISTS.ADULT_DOMAIN_PATTERNS || [];

const DEFAULT_SETTINGS = {
  warningThreshold: 35,
  showBadgeOnSafePages: true,
  demoMode: true,
  progressiveScan: true,
  observationWindowMs: 4000,
  interactionObservationMs: 5000,
  sendFalsePositiveFeedback: true,
  feedbackEndpoint: "http://localhost:8000/feedback/false-positive",
  shadowMode: true,
  reputationEnabled: true,
  reputationEndpoint: "http://localhost:8000/v1/reputation/check",
  sensitivityMode: "BALANCED"
};

let trustedDomainsCache = null;
let riskyCategoriesCache = null;
let detectionPolicyCache = null;
let brandRegistryCache = null;
// Local perceptual-hash results for logo/favicon URLs (offscreen pipeline). The
// pipeline stays inert while the bundled registry ships empty visual hashes and
// the "offscreen" permission is not granted; guarded at every call site.
const visualHashCache = new Map();
const tabNetworkSignals = new Map();
const tabPageDomains = new Map();
const tabPageKeys = new Map();
const tabPageEpochs = new Map();
const tabNavigationIds = new Map();
const tabRescanTimers = new Map();
const tabClearTasks = new Map();
const reputationInFlight = new Set();
const navigationGuard = engineReady ? ArgusNavigationGuard.create() : null;

if (engineReady) {
  initializeNetworkMonitoring();
}

// Ensure all settings — including reputation — always exist in chrome.storage, so a
// fresh install or a partial legacy settings object never leaves reputation missing
// (the live "settings missing -> stays SAFE" bug). Runs on startup, install, and
// browser startup. Existing user choices are preserved by normalizeSettings.
async function ensureSettingsInitialized() {
  try {
    const stored = await chrome.storage.local.get([SETTINGS_KEY]);
    const raw = stored[SETTINGS_KEY];
    const missingKeys = !raw || typeof raw !== "object" ||
      (raw.reputationEnabled === undefined && raw.useReputation === undefined) ||
      !raw.reputationEndpoint || raw.sensitivityMode === undefined;
    if (missingKeys) {
      const merged = normalizeSettings(raw);
      await chrome.storage.local.set({ [SETTINGS_KEY]: merged });
      console.log("[Project Argus] settings initialized; reputation enabled:", merged.reputationEnabled, merged.reputationEndpoint, "sensitivity:", merged.sensitivityMode);
    }
  } catch (error) {
    console.warn("[Project Argus] settings initialization failed", error);
  }
}

ensureSettingsInitialized();
if (chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => ensureSettingsInitialized());
}
if (chrome.runtime && chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => ensureSettingsInitialized());
}

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
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === CLEAR_LAST_SCAN_MESSAGE) {
    clearLastScan(message.tabId)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === PAGE_CHANGED_MESSAGE) {
    const tabId = sender && sender.tab ? sender.tab.id : null;
    if (navigationGuard && Number.isInteger(tabId) && tabId >= 0) {
      clearPageState(tabId, message.payload && message.payload.pageKey);
      if (message.payload && message.payload.domain) {
        tabPageDomains.set(tabId, String(message.payload.domain).toLowerCase());
      }
      // Hand the fresh navigation id back so the content script stops carrying a
      // stale id on subsequent sensitive events (which the guard would reject).
      sendResponse({ ok: true, navigationId: getNavigationId(tabId) });
      return false;
    }
    sendResponse({ ok: true });
    return false;
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

  if (chrome.webRequest.onHeadersReceived) {
    chrome.webRequest.onHeadersReceived.addListener(
      recordResponseHeaders,
      { urls: ["<all_urls>"], types: ["main_frame"] },
      ["responseHeaders"]
    );
  }

  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      tabNetworkSignals.delete(tabId);
      tabPageDomains.delete(tabId);
      tabPageKeys.delete(tabId);
      tabPageEpochs.delete(tabId);
      tabNavigationIds.delete(tabId);
      navigationGuard.clear(tabId);
      const timer = tabRescanTimers.get(tabId);
      if (timer) clearTimeout(timer);
      tabRescanTimers.delete(tabId);
    });
  }

  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
      if (changeInfo.status === "loading" || typeof changeInfo.url === "string") {
        clearPageState(tabId);
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
  if (tabDomain && initiatorDomain && !isSameSiteDomain(tabDomain, initiatorDomain) && Number(details.frameId) === 0 && details.type !== "main_frame") {
    return;
  }
  const referenceDomain = tabDomain || initiatorDomain;
  const isThirdParty = referenceDomain ? !isSameSiteDomain(requestMeta.hostname, referenceDomain) : false;
  const signals = getNetworkSignals(details.tabId);
  const now = Date.now();
  const method = String(details.method || "GET").toUpperCase();
  const isWriteRequest = WRITE_METHODS.has(method);
  const afterFormSubmit = Boolean(signals.lastFormSubmitAt && now - signals.lastFormSubmitAt < SENSITIVE_REQUEST_WINDOW_MS);
  const afterSensitiveFocus = Boolean(signals.lastPasswordFocusAt && now - signals.lastPasswordFocusAt < SENSITIVE_REQUEST_WINDOW_MS);
  const followsSensitiveInteraction = (afterFormSubmit && signals.lastFormWasSensitive) || afterSensitiveFocus;
  const initiatorProtocol = parseUrlMetadata(details.initiator || details.documentUrl || "").protocol;
  const isMixedContent = initiatorProtocol === "https:" && requestMeta.protocol === "http:" && details.type !== "main_frame";
  const destinationRole = classifyDestinationRole({ details, requestMeta, referenceDomain, isThirdParty, isWriteRequest, followsSensitiveInteraction });
  const unknownWrite = destinationRole === "UNKNOWN_WRITE_DESTINATION";
  const unknownBeacon = destinationRole === "UNKNOWN_BEACON";
  // Race-safe beacon flag: recognize a beacon/ping to an unknown third party even
  // when it arrives before the sensitive interaction (destinationRole would not
  // yet be UNKNOWN_BEACON). Used only for retroactive correlation, not live counts.
  const candidateUnknownBeacon = unknownBeacon ||
    ArgusNetworkCorrelation.isUnknownBeaconDestination(details, isThirdParty, isKnownDestinationRole(destinationRole));

  // Runtime messages and webRequest callbacks can arrive in either order. Retain
  // metadata only, briefly, so a later sensitive-submit event can correlate a
  // request that was observed first.
  if (!followsSensitiveInteraction) {
    rememberPotentialSensitiveRequest(signals, {
      at: now,
      isWriteRequest,
      isThirdParty,
      isInsecure: requestMeta.protocol === "http:",
      isUnknownWrite: unknownWrite,
      isUnknownBeacon: candidateUnknownBeacon,
      isQueryImage: details.type === "image" && method === "GET" && requestMeta.hasQuery && isThirdParty,
      // Do not retain the request URL, body, or headers for race correlation.
      details: { type: details.type, method, frameId: details.frameId },
      requestMeta: {
        protocol: requestMeta.protocol,
        hostname: requestMeta.hostname,
        pathname: requestMeta.pathname,
        hasQuery: requestMeta.hasQuery
      },
      destinationRole
    });
  }

  signals.totalRequests += 1;
  if (isThirdParty) {
    signals.thirdPartyRequests += 1;
  }
  if (requestMeta.protocol === "http:") {
    signals.insecureHttpRequests += 1;
  }
  if (isMixedContent) {
    signals.mixedContentRequestCount += 1;
    if (["script", "xmlhttprequest", "sub_frame", "object", "stylesheet"].includes(details.type)) {
      signals.insecureActiveContentRequestCount += 1;
    }
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
  if (afterFormSubmit && unknownWrite) {
    signals.requestsAfterFormSubmit += 1;
    addTimelineEvent(signals, "THIRD_PARTY_AFTER_FORM", now, networkEventMeta(details, requestMeta, destinationRole, followsSensitiveInteraction));
  }
  if (afterSensitiveFocus && (unknownWrite || unknownBeacon)) {
    signals.requestsAfterPasswordFocus += 1;
    addTimelineEvent(signals, "THIRD_PARTY_AFTER_PASSWORD", now, networkEventMeta(details, requestMeta, destinationRole, followsSensitiveInteraction));
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
      if (unknownWrite) {
        signals.crossDomainSensitiveWriteRequests += 1;
        addLimited(signals.unknownSensitiveDestinations, requestMeta.hostname, 20);
        addTimelineEvent(signals, "CROSS_DOMAIN_SENSITIVE_WRITE", now, networkEventMeta(details, requestMeta, destinationRole, true));
      }
    }
  }
  if (["beacon", "ping"].includes(details.type) && followsSensitiveInteraction && unknownBeacon) {
    signals.beaconOrPingAfterSensitiveInput += 1;
    addLimited(signals.unknownSensitiveDestinations, requestMeta.hostname, 20);
    addTimelineEvent(signals, "BEACON_AFTER_SENSITIVE_INPUT", now, networkEventMeta(details, requestMeta, destinationRole, true));
  }
  if (details.type === "image" && method === "GET" && requestMeta.hasQuery && isThirdParty &&
    afterFormSubmit && signals.lastFormWasSensitive) {
    signals.queryBearingGetAfterSensitiveForm += 1;
    addLimited(signals.unknownSensitiveDestinations, requestMeta.hostname, 20);
    addTimelineEvent(signals, "QUERY_GET_AFTER_SENSITIVE_FORM", now, networkEventMeta(details, requestMeta, "UNKNOWN_BEACON", true));
  }
  if (signals.lastFormSubmitAt && now - signals.lastFormSubmitAt < TEMPORAL_WINDOW_MS && isThirdParty && details.type === "main_frame") {
    signals.formSubmitThenCrossDomainRedirectCount += 1;
    addTimelineEvent(signals, "CROSS_DOMAIN_REDIRECT_AFTER_FORM", now);
  }
  if (isThirdParty && isSuspiciousRequestType(details.type)) {
    addLimited(signals.suspiciousRequestDomains, requestMeta.hostname, 30);
  }
  signals.destinationRoleCounts[destinationRole] = (signals.destinationRoleCounts[destinationRole] || 0) + 1;
  if (destinationRole === "EXECUTABLE_DOWNLOAD_SOURCE") addLimited(signals.executableDownloadDomains, requestMeta.hostname, 10);

  signals.updatedAt = now;
  tabNetworkSignals.set(details.tabId, signals);

  if ((afterFormSubmit && isWriteRequest) ||
    (["beacon", "ping"].includes(details.type) && followsSensitiveInteraction) ||
    (details.type === "image" && method === "GET" && requestMeta.hasQuery && isThirdParty && afterFormSubmit && signals.lastFormWasSensitive)) {
    schedulePageRescan(details.tabId, 300);
  }
}

function recordResponseHeaders(details) {
  if (!details || details.tabId < 0 || details.type !== "main_frame") return;
  const signals = getNetworkSignals(details.tabId);
  const headerNames = new Set(toArray(details.responseHeaders).map((header) => String(header && header.name || "").toLowerCase()));
  signals.responseHeadersObserved = true;
  signals.hasContentSecurityPolicy = headerNames.has("content-security-policy");
  signals.hasStrictTransportSecurity = headerNames.has("strict-transport-security");
  signals.hasXContentTypeOptions = headerNames.has("x-content-type-options");
  signals.hasReferrerPolicy = headerNames.has("referrer-policy");
  signals.hasPermissionsPolicy = headerNames.has("permissions-policy");
  signals.updatedAt = Date.now();
  tabNetworkSignals.set(details.tabId, signals);
}

function recordPageEvent(type, payload, sender) {
  if (!navigationGuard) return;
  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (!Number.isInteger(tabId) || tabId < 0) {
    return;
  }
  const signals = getNetworkSignals(tabId);
  if (!navigationGuard.matches({ tabId, pageKey: payload && payload.pageKey, navigationId: payload && payload.navigationId })) {
    signals.pageEventsRejected += 1;
    signals.lastPageEventRejectReason = "NAVIGATION_MISMATCH";
    signals.updatedAt = Date.now();
    tabNetworkSignals.set(tabId, signals);
    return;
  }

  signals.pageEventsAccepted += 1;
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
    if (signals.lastFormWasSensitive) {
      addTimelineEvent(signals, "SENSITIVE_FORM_SUBMIT", now);
      correlatePendingSensitiveRequests(signals, now, "FORM_SUBMIT");
    }
  }
  if (type === PASSWORD_FOCUS_MESSAGE) {
    correlatePendingSensitiveRequests(signals, now, "SENSITIVE_FOCUS");
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

  const scheduledNavigationId = getNavigationId(tabId);
  const timer = setTimeout(() => {
    tabRescanTimers.delete(tabId);
    if (getNavigationId(tabId) !== scheduledNavigationId) return;
    chrome.tabs.sendMessage(tabId, { type: RESCAN_MESSAGE, scanPhase: "PRELIMINARY" }, () => {
      chrome.runtime.lastError;
    });
    loadSettings().then((settings) => {
      setTimeout(() => {
        if (getNavigationId(tabId) !== scheduledNavigationId) return;
        chrome.tabs.sendMessage(tabId, { type: RESCAN_MESSAGE, scanPhase: "INTERACTION_FINAL" }, () => {
          chrome.runtime.lastError;
        });
      }, settings.interactionObservationMs);
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
    unknownSensitiveDestinations: [],
    executableDownloadDomains: [],
    destinationRoleCounts: {},
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
    mixedContentRequestCount: 0,
    insecureActiveContentRequestCount: 0,
    responseHeadersObserved: false,
    hasContentSecurityPolicy: false,
    hasStrictTransportSecurity: false,
    hasXContentTypeOptions: false,
    hasReferrerPolicy: false,
    hasPermissionsPolicy: false,
    downloadClickCount: 0,
    formSubmitThenCrossDomainRedirectCount: 0,
    downloadAfterFormSubmitCount: 0,
    recentEvents: [],
    pageEventsAccepted: 0,
    pageEventsRejected: 0,
    lastPageEventRejectReason: "",
    retroactiveCorrelations: 0,
    recentPotentialSensitiveRequests: [],
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
    unknownSensitiveDestinations: signals.unknownSensitiveDestinations.slice(0, 20),
    executableDownloadDomains: signals.executableDownloadDomains.slice(0, 10),
    destinationRoles: Object.keys(signals.destinationRoleCounts),
    destinationRoleCounts: { ...signals.destinationRoleCounts },
    pageEventsAccepted: signals.pageEventsAccepted,
    pageEventsRejected: signals.pageEventsRejected,
    retroactiveCorrelations: signals.retroactiveCorrelations,
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

function exportSecuritySignals(tabId) {
  const signals = getNetworkSignals(tabId);
  const protectedHeaders = [
    signals.hasContentSecurityPolicy,
    signals.hasStrictTransportSecurity,
    signals.hasXContentTypeOptions,
    signals.hasReferrerPolicy,
    signals.hasPermissionsPolicy
  ].filter(Boolean).length;
  return {
    responseHeadersObserved: Boolean(signals.responseHeadersObserved),
    hasContentSecurityPolicy: Boolean(signals.hasContentSecurityPolicy),
    hasStrictTransportSecurity: Boolean(signals.hasStrictTransportSecurity),
    hasXContentTypeOptions: Boolean(signals.hasXContentTypeOptions),
    hasReferrerPolicy: Boolean(signals.hasReferrerPolicy),
    hasPermissionsPolicy: Boolean(signals.hasPermissionsPolicy),
    missingSecurityHeaderCount: signals.responseHeadersObserved ? 5 - protectedHeaders : 0,
    mixedContentRequestCount: Number(signals.mixedContentRequestCount) || 0,
    insecureActiveContentRequestCount: Number(signals.insecureActiveContentRequestCount) || 0
  };
}

function addTimelineEvent(signals, type, at, metadata = {}) {
  signals.recentEvents = Array.isArray(signals.recentEvents) ? signals.recentEvents : [];
  signals.recentEvents.push({ type, at, ...metadata });
  signals.recentEvents = signals.recentEvents
    .filter((event) => at - event.at <= TEMPORAL_WINDOW_MS)
    .slice(-40);
}

function rememberPotentialSensitiveRequest(signals, candidate) {
  const relevant = candidate.isUnknownWrite || candidate.isUnknownBeacon || candidate.isQueryImage ||
    (candidate.isWriteRequest && candidate.isInsecure);
  if (!relevant) return;
  signals.recentPotentialSensitiveRequests = Array.isArray(signals.recentPotentialSensitiveRequests)
    ? signals.recentPotentialSensitiveRequests : [];
  signals.recentPotentialSensitiveRequests.push({ ...candidate, correlated: false });
  signals.recentPotentialSensitiveRequests = signals.recentPotentialSensitiveRequests
    .filter((item) => candidate.at - item.at <= SENSITIVE_REQUEST_WINDOW_MS)
    .slice(-20);
}

function correlatePendingSensitiveRequests(signals, now, trigger) {
  const candidates = Array.isArray(signals.recentPotentialSensitiveRequests) ? signals.recentPotentialSensitiveRequests : [];
  for (const candidate of candidates) {
    if (candidate.correlated || now - candidate.at < 0 || now - candidate.at > SENSITIVE_REQUEST_WINDOW_MS) continue;
    const effects = ArgusNetworkCorrelation.correlationEffects(candidate, trigger);
    if (!effects.accept) continue;

    candidate.correlated = true;
    signals.retroactiveCorrelations += 1;

    // A cross-domain write that arrived first is surfaced as third-party-after-form
    // in the live path; mirror that timeline event here for parity.
    if (effects.counters.requestsAfterFormSubmit) {
      addTimelineEvent(signals, "THIRD_PARTY_AFTER_FORM", now, networkEventMeta(candidate.details, candidate.requestMeta, candidate.destinationRole, true));
    }
    for (const [counter, amount] of Object.entries(effects.counters)) {
      signals[counter] = (Number(signals[counter]) || 0) + amount;
    }
    if (effects.destination) {
      addLimited(signals.unknownSensitiveDestinations, candidate.requestMeta.hostname, 20);
    }
    for (const event of effects.timeline) {
      addTimelineEvent(signals, event.type, now, networkEventMeta(candidate.details, candidate.requestMeta, event.roleOverride || candidate.destinationRole, true));
    }
  }
}

// Destination roles that classifyDestinationRole assigns to recognized providers,
// CDNs, and same-site traffic. Used to decide whether a beacon/ping destination
// is "unknown" independently of interaction timing.
function isKnownDestinationRole(role) {
  return [
    "KNOWN_IDENTITY_PROVIDER", "KNOWN_PAYMENT_PROVIDER", "KNOWN_ANALYTICS", "KNOWN_AD_NETWORK",
    "CDN", "SSO_REDIRECT", "SAME_SITE_API", "STATIC_ASSET", "FIRST_PARTY_WRITE"
  ].includes(role);
}

function classifyDestinationRole({ details, requestMeta, referenceDomain, isThirdParty, isWriteRequest, followsSensitiveInteraction }) {
  const domain = requestMeta.hostname;
  const path = String(requestMeta.pathname || "").toLowerCase();
  if (/\.(apk|exe|msi|dmg|pkg)(?:$|\/)/i.test(path)) return "EXECUTABLE_DOWNLOAD_SOURCE";
  if (!isThirdParty && isWriteRequest) return "FIRST_PARTY_WRITE";
  if (!isThirdParty && ["xmlhttprequest", "fetch"].includes(details.type)) return "SAME_SITE_API";
  if (["image", "stylesheet", "font", "media"].includes(details.type)) return isThirdParty ? "STATIC_ASSET" : "SAME_SITE_API";
  if (domainMatchesAny(domain, KNOWN_IDENTITY_DOMAINS)) return details.type === "main_frame" ? "SSO_REDIRECT" : "KNOWN_IDENTITY_PROVIDER";
  if (domainMatchesAny(domain, KNOWN_PAYMENT_DOMAINS)) return "KNOWN_PAYMENT_PROVIDER";
  if (domainMatchesAny(domain, KNOWN_ANALYTICS_DOMAINS)) return "KNOWN_ANALYTICS";
  if (domainMatchesAny(domain, KNOWN_AD_DOMAINS)) return "KNOWN_AD_NETWORK";
  if (CDN_DOMAIN_HINTS.some((hint) => domain.includes(hint))) return "CDN";
  if (isThirdParty && ["beacon", "ping"].includes(details.type) && followsSensitiveInteraction) return "UNKNOWN_BEACON";
  if (isThirdParty && isWriteRequest) return "UNKNOWN_WRITE_DESTINATION";
  return isThirdParty ? "UNKNOWN_READ_DESTINATION" : "SAME_SITE_API";
}

function domainMatchesAny(domain, candidates) {
  return candidates.some((candidate) => domain === candidate || domain.endsWith(`.${candidate}`));
}

function networkEventMeta(details, requestMeta, destinationRole, sensitiveContextPresent) {
  return {
    eventType: String(details.type || "request").toUpperCase(),
    scanPhase: sensitiveContextPresent ? "POST_INTERACTION" : "POST_LOAD",
    destinationRole,
    destination: requestMeta.hostname,
    method: String(details.method || "GET").toUpperCase(),
    protocol: requestMeta.protocol,
    frameId: Number(details.frameId) || 0,
    sensitiveContextPresent: Boolean(sensitiveContextPresent),
    evidenceIds: []
  };
}

function exportInteractionTimeline(tabId, navigationId) {
  const signals = getNetworkSignals(tabId);
  return signals.recentEvents.slice(-40).map((event) => ({
    tabId,
    navigationId,
    frameId: Number(event.frameId) || 0,
    timestamp: new Date(event.at).toISOString(),
    eventType: event.eventType || event.type,
    scanPhase: event.scanPhase || phaseForEvent(event.type),
    destinationRole: event.destinationRole || "NONE",
    method: event.method || "NONE",
    protocol: event.protocol || "NONE",
    sensitiveContextPresent: Boolean(event.sensitiveContextPresent || /SENSITIVE|PASSWORD|FORM_SUBMIT/.test(event.type)),
    evidenceIds: Array.isArray(event.evidenceIds) ? event.evidenceIds.slice(0, 8) : []
  }));
}

function phaseForEvent(type) {
  if (/DOWNLOAD/.test(type)) return "DOWNLOAD";
  if (/FORM_SUBMIT/.test(type)) return "FORM_SUBMIT";
  if (/PASSWORD|SENSITIVE/.test(type)) return "SENSITIVE_INPUT";
  if (/AFTER|BEACON|WRITE|REDIRECT/.test(type)) return "POST_INTERACTION";
  return "POST_LOAD";
}

function clearPageState(tabId, nextPageKey) {
  if (!navigationGuard) return;
  tabNetworkSignals.delete(tabId);
  tabPageDomains.delete(tabId);
  if (nextPageKey) tabPageKeys.set(tabId, String(nextPageKey));
  else tabPageKeys.delete(tabId);
  tabPageEpochs.set(tabId, (tabPageEpochs.get(tabId) || 0) + 1);
  const session = navigationGuard.begin(tabId, nextPageKey, tabPageEpochs.get(tabId));
  tabNavigationIds.set(tabId, session.navigationId);

  const timer = tabRescanTimers.get(tabId);
  if (timer) clearTimeout(timer);
  tabRescanTimers.delete(tabId);

  const previous = tabClearTasks.get(tabId) || Promise.resolve();
  const task = previous
    .catch(() => undefined)
    .then(() => clearLastScan(tabId))
    .catch((error) => console.warn("[Project Argus] failed to clear stale tab scan", error));
  tabClearTasks.set(tabId, task);
  task.finally(() => {
    if (tabClearTasks.get(tabId) === task) tabClearTasks.delete(tabId);
  });
}

// Fail-closed result when the engine modules are not loaded. Deliberately NOT
// SAFE — a green badge would falsely reassure the user that the page was checked.
function engineUnavailableResult(pageData, sender) {
  const tabId = sender && sender.tab ? sender.tab.id : null;
  const scanPhase = String(pageData && pageData.scanPhase || "FINAL").toUpperCase();
  return {
    url: String(pageData && pageData.url || ""),
    domain: String(pageData && pageData.domain || "").toLowerCase(),
    tabId,
    timestamp: new Date().toISOString(),
    isTrustedDomain: false,
    isSearchEnginePage: false,
    risk: {
      score: 0, riskScore: 0, level: "UNAVAILABLE", status: "UNAVAILABLE", category: "UNAVAILABLE",
      confidence: "LOW", evidenceLevel: "NONE", evidenceIds: [], evidenceGroups: [],
      reasons: ["Project Argus could not scan this page: the local engine failed to load. Reload the extension at chrome://extensions."],
      source: "ENGINE_UNAVAILABLE", policyVersion: POLICY_VERSION,
      warningAllowed: false, overlayAllowed: false, shouldWarn: false
    },
    modelStatus: { mode: "ENGINE_UNAVAILABLE", externalAi: false, engine: "ARGUS_EVIDENCE_ENGINE", message: "Local engine failed to load." },
    scanPhase, isFinal: true,
    modelVersion: MODEL_VERSION, policyVersion: POLICY_VERSION, reportSchemaVersion: REPORT_SCHEMA_VERSION,
    source: "ENGINE_UNAVAILABLE"
  };
}

async function handlePageScan(pageData, sender) {
  if (!engineReady) {
    return engineUnavailableResult(pageData, sender);
  }
  const tabId = sender && sender.tab ? sender.tab.id : null;
  const pageEpoch = Number.isInteger(tabId) ? (tabPageEpochs.get(tabId) || 0) : 0;
  if (Number.isInteger(tabId) && tabClearTasks.has(tabId)) {
    await tabClearTasks.get(tabId);
  }
  if (Number.isInteger(tabId) && pageEpoch !== (tabPageEpochs.get(tabId) || 0)) {
    throw new Error("Stale scan ignored after page navigation.");
  }
  if (Number.isInteger(tabId) && tabPageKeys.has(tabId) && pageData && pageData.pageKey !== tabPageKeys.get(tabId)) {
    throw new Error("Stale scan ignored because the page identity changed.");
  }
  const settings = await loadSettings();
  const trustedDomains = await loadTrustedDomains();
  const riskyCategories = await loadRiskyCategories();
  const detectionPolicy = await loadDetectionPolicy();
  const brandRegistry = await loadBrandRegistry();
  const scanPhase = String(pageData && pageData.scanPhase || "FINAL").toUpperCase();
  const signals = normalizeSignals(pageData, trustedDomains);
  // The brand-identity registry is the live brand source for the offline lookalike
  // detector; the engine falls back to the curated LOOKALIKE_BRANDS list when this
  // is empty (node tests, registry load failure).
  signals.lookalikeBrandDomains = flattenRegistryDomains(brandRegistry);
  signals.identitySignals = ArgusBrandIdentity.analyze({ ...pageData, ...signals }, brandRegistry);
  if (["FINAL", "INTERACTION_FINAL"].includes(scanPhase) && signals.identitySignals.visualReferenceAvailable && signals.identitySignals.domainMismatch) {
    // Inert while the bundled registry ships no visual hashes and the "offscreen"
    // permission is absent; requestLocalVisualHash returns null in both cases.
    const visualHashes = await hashLogoCandidates(pageData && pageData.logoCandidates);
    if (visualHashes.length > 0) signals.identitySignals = ArgusBrandIdentity.analyze({ ...pageData, ...signals, visualHashes }, brandRegistry);
  }
  if (Number.isInteger(tabId) && tabId >= 0) {
    tabPageDomains.set(tabId, signals.domain);
    if (signals.pageKey) {
      tabPageKeys.set(tabId, signals.pageKey);
      navigationGuard.note(tabId, signals.pageKey);
    }
    signals.networkSignals = exportNetworkSignals(tabId);
    signals.securitySignals = mergeSecuritySignals(signals.securitySignals, exportSecuritySignals(tabId));
  }
  const ruleRisk = calculateRuleRisk(signals, riskyCategories, detectionPolicy);
  const navigationId = getNavigationId(tabId);
  const frameId = Number(sender && sender.frameId) || 0;
  // Domain reputation: use a fresh cached verdict for this scan; if none is cached,
  // fetch it in the background and trigger a prompt final rescan so the verdict is
  // applied. Non-blocking so page scanning is never delayed on the lookup.
  const reputation = await resolveReputationContext(signals, settings, tabId);
  const reputationContext = reputation.context;
  // Single injection point: a MALICIOUS verdict becomes direct evidence inside the
  // policy (REPUTATION_BLOCKLISTED via context.reputation). Only the graded
  // RISKY_CONTEXT verdict is injected here as ordinary evidence.
  addReputationEvidence(ruleRisk, reputationContext);
  const policyDecision = ArgusEvidencePolicy.decide({
    legacyRisk: ruleRisk,
    context: {
      tabId, navigationId, frameId, scanPhase,
      timestamp: new Date().toISOString(),
      isTrustedDomain: signals.isTrustedDomain,
      isSearchEnginePage: signals.isSearchEnginePage,
      networkSignals: signals.networkSignals,
      destinationRoles: signals.networkSignals && signals.networkSignals.destinationRoles,
      reputation: reputationContext,
      identitySignals: signals.identitySignals,
      sensitivityMode: settings.sensitivityMode,
      sensitiveInteractionObserved: Boolean(signals.networkSignals && signals.networkSignals.sensitiveInteractionObserved)
    }
  });
  const modelStatus = {
    mode: ruleRisk.source || "LOCAL_ENSEMBLE",
    externalAi: false,
    engine: "ARGUS_EVIDENCE_ENGINE",
    policyVersion: POLICY_VERSION,
    modelVersion: ruleRisk.modelAnalysis && ruleRisk.modelAnalysis.version || "unavailable",
    message: "Project Argus local evidence ensemble active."
  };

  // Single authority: policyDecision is spread AFTER ruleRisk so the evidence
  // decision policy owns every decision field (status, level, score, riskScore,
  // confidence, reasons, warningAllowed, source, policyVersion). ruleRisk only
  // contributes evidence data and advisory magnitude (legacyScore/legacyLevel).
  // The two version concepts are kept distinct: policyVersion = decision policy
  // (evidence-first-v2); detectionPolicyVersion = the weights/config version.
  const finalRisk = {
    ...ruleRisk,
    ...policyDecision,
    category: policyDecision.status === "SAFE" ? "SAFE" : ["MONITORING", "UNCERTAIN"].includes(policyDecision.status) ? "UNCONFIRMED" : policyDecision.status === "RISKY_CONTEXT" ? policyDecision.riskContext : ruleRisk.category,
    evidence: ruleRisk.evidence || [],
    toolResults: ruleRisk.toolResults || [],
    modelAnalysis: ruleRisk.modelAnalysis || null,
    policyVersion: POLICY_VERSION,
    detectionPolicyVersion: ruleRisk.detectionPolicyVersion || (detectionPolicy && detectionPolicy.version) || "unknown",
    legacyLevel: ruleRisk.level,
    legacyScore: ruleRisk.score
  };

  const isFinal = scanPhase === "FINAL" || scanPhase === "INTERACTION_FINAL" || !settings.progressiveScan;
  finalRisk.shouldWarn = isFinal && policyDecision.warningAllowed;
  finalRisk.warningAllowed = isFinal && policyDecision.warningAllowed;
  finalRisk.overlayEligible = isFinal && policyDecision.overlayAllowed;
  finalRisk.overlayAllowed = false;
  finalRisk.demoMode = settings.demoMode;

  const scanResult = {
    ...signals,
    timestamp: new Date().toISOString(),
    tabId,
    risk: finalRisk,
    ruleBasedRisk: ruleRisk,
    modelStatus,
    settings: publicSettings(settings),
    scanPhase,
    isFinal,
    navigationId,
    frameId,
    modelVersion: MODEL_VERSION,
    policyVersion: POLICY_VERSION,
    detectionPolicyVersion: finalRisk.detectionPolicyVersion,
    reportSchemaVersion: REPORT_SCHEMA_VERSION,
    reputation: reputationContext || null,
    interactionTimeline: exportInteractionTimeline(tabId, navigationId),
    shadowComparison: settings.shadowMode ? {
      legacyStatus: ruleRisk.level,
      legacyScore: ruleRisk.score,
      detectionPolicyVersion: finalRisk.detectionPolicyVersion,
      evidenceFirstStatus: finalRisk.status,
      evidenceFirstScore: finalRisk.score,
      evidenceIds: finalRisk.evidenceIds,
      modelScore: finalRisk.model && finalRisk.model.score,
      modelOnly: finalRisk.modelOnly,
      overlayAllowed: false,
      overlayEligible: finalRisk.overlayEligible,
      timestamp: new Date().toISOString(),
      modelVersion: MODEL_VERSION,
      policyVersion: POLICY_VERSION
    } : null,
    source: finalRisk.source,
    debug: {
      domain: signals.domain,
      isTrustedDomain: signals.isTrustedDomain,
      isSearchEnginePage: signals.isSearchEnginePage,
      ruleScore: ruleRisk.score,
      finalScore: finalRisk.score,
      finalLevel: finalRisk.level,
      confidence: finalRisk.confidence,
      policyVersion: POLICY_VERSION,
      model: finalRisk.source,
      warningThreshold: settings.warningThreshold,
      pipeline: {
        engineSource: ruleRisk.source || "UNKNOWN",
        engineEvidenceIds: (ruleRisk.evidence || []).map((item) => item.id).slice(0, 30),
        engineDirectEvidenceIds: finalRisk.engineDirectEvidenceIds || [],
        telemetryDirectEvidenceIds: finalRisk.telemetryDirectEvidenceIds || [],
        reputationDirectEvidenceIds: finalRisk.reputationDirectEvidenceIds || [],
        reputation: reputation.diag,
        evidenceGroups: finalRisk.evidenceGroups || [],
        observedEvidenceGroups: finalRisk.observedEvidenceGroups || [],
        modelOnly: Boolean(finalRisk.modelOnly),
        scanPhase,
        navigationId,
        telemetry: {
          pageEventsAccepted: Number(signals.networkSignals && signals.networkSignals.pageEventsAccepted) || 0,
          pageEventsRejected: Number(signals.networkSignals && signals.networkSignals.pageEventsRejected) || 0,
          retroactiveCorrelations: Number(signals.networkSignals && signals.networkSignals.retroactiveCorrelations) || 0,
          sensitiveWrites: Number(signals.networkSignals && signals.networkSignals.sensitiveWriteRequestsAfterFormSubmit) || 0,
          crossDomainSensitiveWrites: Number(signals.networkSignals && signals.networkSignals.crossDomainSensitiveWriteRequests) || 0,
          sensitiveBeacons: Number(signals.networkSignals && signals.networkSignals.beaconOrPingAfterSensitiveInput) || 0
        }
      }
    }
  };

  console.log("[Project Argus] scan", scanResult.debug);
  console.log("[Project Argus] signals", {
    apkLinks: signals.apkLinks.length,
    foundStoreKeywords: signals.foundStoreKeywords,
    contentRiskSignals: signals.contentRiskSignals,
    suspiciousDomainSignals: signals.suspiciousDomainSignals
  });

  if (Number.isInteger(tabId) && pageEpoch !== (tabPageEpochs.get(tabId) || 0)) {
    throw new Error("Stale scan result discarded after page navigation.");
  }
  await saveScanResult(scanResult);

  return scanResult;
}

async function loadTrustedDomains() {
  if (trustedDomainsCache) {
    return trustedDomainsCache;
  }

  // Baseline trusted domains live in the shared module (single source with
  // content.js — F8). trusted_domains.json holds optional local additions unioned
  // on top; content.js sees the same baseline, so the two can no longer diverge.
  const baseline = SHARED_LISTS.TRUSTED_DOMAINS || [];
  const additions = await fetchJson("trusted_domains.json", []);
  trustedDomainsCache = unique(baseline.concat(toArray(additions)));
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

async function loadBrandRegistry() {
  if (brandRegistryCache) return brandRegistryCache;
  const bootstrap = await fetchJson("engine/brand_registry.json", { schemaVersion: 1, version: "unavailable", brands: [] });
  brandRegistryCache = ArgusBrandIdentity.validateRegistry(bootstrap) ? bootstrap : { schemaVersion: 1, version: "invalid", brands: [] };
  try {
    const stored = await chrome.storage.local.get(["argusSignedBrandRegistry"]);
    const envelope = stored.argusSignedBrandRegistry;
    if (envelope && await ArgusBrandIdentity.verifySignedEnvelope(envelope) && ArgusBrandIdentity.validateRegistry(envelope.payload) &&
      compareRegistryVersions(envelope.payload.version, brandRegistryCache.version) >= 0) {
      brandRegistryCache = envelope.payload;
    }
  } catch (error) {
    console.warn("[Project Argus] signed brand registry was rejected; bundled registry remains active.", error);
  }
  return brandRegistryCache;
}

function compareRegistryVersions(left, right) {
  return String(left || "").localeCompare(String(right || ""), undefined, { numeric: true, sensitivity: "base" });
}

// Flatten the registry's official/authentication domains into the brand list the
// offline lookalike detector consumes (signals.lookalikeBrandDomains).
function flattenRegistryDomains(registry) {
  const brands = registry && Array.isArray(registry.brands) ? registry.brands : [];
  const domains = [];
  for (const brand of brands) {
    for (const domain of toArray(brand && brand.officialDomains)) domains.push(String(domain).toLowerCase());
    for (const domain of toArray(brand && brand.authenticationDomains)) domains.push(String(domain).toLowerCase());
  }
  return unique(domains);
}

async function hashLogoCandidates(values) {
  const urls = toArray(values).slice(0, 5).filter((value) => {
    try { return new URL(String(value)).protocol === "https:"; } catch (error) { return false; }
  });
  const hashes = [];
  for (const url of urls) {
    const cached = visualHashCache.get(url);
    if (cached && cached.expiresAt > Date.now()) {
      if (cached.hash) hashes.push(cached.hash);
      continue;
    }
    const hash = await requestLocalVisualHash(url);
    visualHashCache.set(url, { hash, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
    if (hash) hashes.push(hash);
  }
  return unique(hashes);
}

async function requestLocalVisualHash(url) {
  // Requires the "offscreen" permission, which the shipped manifest deliberately
  // omits until reviewed visual hashes exist in a signed registry release.
  if (!chrome.offscreen || typeof chrome.offscreen.createDocument !== "function") return null;
  try {
    await ensureOffscreenDocument();
    const response = await chrome.runtime.sendMessage({ type: "ARGUS_HASH_IMAGE", url });
    return response && response.ok && /^[0-9a-f]{16}$/i.test(response.hash) ? response.hash.toLowerCase() : null;
  } catch (error) {
    return null;
  }
}

async function ensureOffscreenDocument() {
  const offscreenUrl = chrome.runtime.getURL("offscreen.html");
  if (chrome.runtime.getContexts) {
    const contexts = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"], documentUrls: [offscreenUrl] });
    if (contexts.length > 0) return;
  }
  try {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["BLOBS"],
      justification: "Decode small public logo and favicon images locally to compute privacy-safe perceptual hashes."
    });
  } catch (error) {
    if (!/single offscreen|already exists/i.test(String(error && error.message || error))) throw error;
  }
}

// Graded reputation evidence. Only the RISKY_CONTEXT verdict is injected here: a
// MALICIOUS verdict must NOT be injected as evidence — it is consumed exclusively
// by the evidence policy as direct evidence (REPUTATION_BLOCKLISTED) via
// context.reputation, so one blocklist hit can never count twice.
function addReputationEvidence(ruleRisk, reputation) {
  if (!ruleRisk || !Array.isArray(ruleRisk.evidence) || !reputation) return;
  if (String(reputation.verdict || "").toUpperCase() === "RISKY_CONTEXT") {
    ruleRisk.evidence.push({
      id: "REPUTATION_RISKY_CONTEXT", tool: "REPUTATION_ANALYZER", category: "GAMBLING_UNVERIFIED",
      priority: 2, points: 20, confidence: reputation.confidence === "HIGH" ? 0.9 : 0.75,
      severity: "medium", message: "A reviewed local or external source classifies this hostname as an unverified risky operator.", decisive: false
    });
  }
}

// Reputation lookup (P1). Delegates to the dependency-injected ArgusReputationClient
// (chrome.* wired in via `deps`) so the exact client logic is covered end-to-end by
// tests against a real backend. Returns { context, diag }; diag is surfaced in
// scanResult.debug.pipeline.reputation.
function reputationDeps() {
  return {
    storageGet: (keys) => chrome.storage.local.get(keys),
    storageSet: (obj) => chrome.storage.local.set(obj),
    fetchImpl: (url, opts) => fetch(url, opts),
    getNavigationId,
    scheduleRescan: (tabId, scanPhase) => chrome.tabs.sendMessage(tabId, { type: RESCAN_MESSAGE, scanPhase }, () => chrome.runtime.lastError),
    inFlight: reputationInFlight,
    now: () => Date.now(),
    log: (diag) => console.log("[Project Argus] reputation lookup", diag)
  };
}

async function resolveReputationContext(signals, settings, tabId) {
  if (typeof ArgusReputationClient === "undefined") {
    return { context: undefined, diag: { enabled: Boolean(settings.reputationEnabled), reason: "client_unavailable", cache: "n/a" } };
  }
  return ArgusReputationClient.resolve(signals, settings, tabId, reputationDeps());
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
    demoMode: raw.demoMode !== false,
    progressiveScan: raw.progressiveScan !== false,
    observationWindowMs: Math.max(2000, Math.min(10000, Number(raw.observationWindowMs) || DEFAULT_SETTINGS.observationWindowMs)),
    interactionObservationMs: Math.max(2000, Math.min(15000, Number(raw.interactionObservationMs) || DEFAULT_SETTINGS.interactionObservationMs)),
    sendFalsePositiveFeedback: raw.sendFalsePositiveFeedback !== false,
    feedbackEndpoint: normalizeFeedbackEndpoint(raw.feedbackEndpoint),
    shadowMode: raw.shadowMode !== false,
    // Canonical key is reputationEnabled. Migration: a pre-merge explicit
    // useReputation:false opt-out is preserved; reputationEnabled wins when set.
    reputationEnabled: raw.reputationEnabled !== undefined ? raw.reputationEnabled !== false : raw.useReputation !== false,
    reputationEndpoint: normalizeLoopbackEndpoint(raw.reputationEndpoint, DEFAULT_SETTINGS.reputationEndpoint),
    sensitivityMode: ["CONSERVATIVE", "BALANCED", "PROTECTIVE"].includes(String(raw.sensitivityMode || "").toUpperCase()) ? String(raw.sensitivityMode).toUpperCase() : DEFAULT_SETTINGS.sensitivityMode
  };
}

// Reputation endpoint is loopback-pinned like the feedback endpoint (F16): the
// lookup is proxied through the LOCAL backend, never an arbitrary external host.
function normalizeLoopbackEndpoint(value, fallback) {
  return typeof ArgusFeedbackEndpoint !== "undefined"
    ? ArgusFeedbackEndpoint.normalizeFeedbackEndpoint(value, fallback)
    : fallback;
}

function normalizeFeedbackEndpoint(value) {
  // Loopback-only enforcement lives in the shared ArgusFeedbackEndpoint module so
  // the worker and the options page agree (F16). Falls back to the default local
  // collector if the module is unavailable (degraded mode).
  return typeof ArgusFeedbackEndpoint !== "undefined"
    ? ArgusFeedbackEndpoint.normalizeFeedbackEndpoint(value, DEFAULT_SETTINGS.feedbackEndpoint)
    : DEFAULT_SETTINGS.feedbackEndpoint;
}

function isLoopbackHost(hostname) {
  return typeof ArgusFeedbackEndpoint !== "undefined" && ArgusFeedbackEndpoint.isLoopbackHost(hostname);
}

function publicSettings(settings) {
  return {
    warningThreshold: settings.warningThreshold,
    showBadgeOnSafePages: settings.showBadgeOnSafePages,
    demoMode: settings.demoMode,
    progressiveScan: settings.progressiveScan,
    observationWindowMs: settings.observationWindowMs,
    interactionObservationMs: settings.interactionObservationMs,
    shadowMode: settings.shadowMode,
    reputationEnabled: settings.reputationEnabled,
    sensitivityMode: settings.sensitivityMode
  };
}

function getNavigationId(tabId) {
  if (!navigationGuard || !Number.isInteger(tabId) || tabId < 0) return "nav-detached";
  if (!tabNavigationIds.has(tabId)) {
    const session = navigationGuard.ensure(tabId, tabPageKeys.get(tabId), tabPageEpochs.get(tabId) || 0);
    tabNavigationIds.set(tabId, session.navigationId);
  }
  return tabNavigationIds.get(tabId);
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
  const foundPaymentWalletKeywords = toArray(pageData.foundPaymentWalletKeywords);
  const foundGovernmentKeywords = toArray(pageData.foundGovernmentKeywords);
  const foundTelecomUtilityKeywords = toArray(pageData.foundTelecomUtilityKeywords);
  const foundDeliveryKeywords = toArray(pageData.foundDeliveryKeywords);
  const foundPlatformAccountKeywords = toArray(pageData.foundPlatformAccountKeywords);
  const foundJobCharityFeeKeywords = toArray(pageData.foundJobCharityFeeKeywords);
  const foundTechSupportKeywords = toArray(pageData.foundTechSupportKeywords);
  const foundPopupAbuseKeywords = toArray(pageData.foundPopupAbuseKeywords);
  const foundFakeShoppingKeywords = toArray(pageData.foundFakeShoppingKeywords);
  const foundPrizeKeywords = toArray(pageData.foundPrizeKeywords);
  const foundPiratedKeywords = toArray(pageData.foundPiratedKeywords);
  const suspiciousDomainSignals = toArray(pageData.suspiciousDomainSignals).concat(getSuspiciousDomainSignals(domain));
  const domainCategorySignals = getDomainCategorySignals(domain);
  const dataLeakSignals = normalizeDataLeakSignals(pageData.dataLeakSignals);
  const securitySignals = normalizeSecuritySignals(pageData.securitySignals);
  const urlLexicalSignals = normalizeUrlLexicalSignals(pageData.urlLexicalSignals);
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
    pageKey: String(pageData.pageKey || "").slice(0, 500),
    pageProtocol: String(pageData.pageProtocol || parseUrlMetadata(url).protocol || ""),
    urlLexicalSignals,
    isTrustedDomain: isTrusted,
    isSearchEnginePage: isSearchEngine,
    passwordFieldCount: Number(pageData.passwordFieldCount) || 0,
    hasPasswordField: Boolean(pageData.hasPasswordField) || Number(pageData.passwordFieldCount) > 0,
    hasOTP: Boolean(pageData.hasOTP),
    hasLoginKeyword: Boolean(pageData.hasLoginKeyword),
    hasSensitiveActionSurface: Boolean(pageData.hasSensitiveActionSurface),
    sensitiveActionKinds: toArray(pageData.sensitiveActionKinds).slice(0, 10),
    apkLinks,
    buttonTexts: toArray(pageData.buttonTexts),
    anchorHrefs: toArray(pageData.anchorHrefs),
    foundStoreKeywords,
    suspiciousDomainSignals: unique(suspiciousDomainSignals),
    foundGamblingKeywords,
    foundAdultKeywords,
    foundBankingKeywords,
    foundInvestmentKeywords,
    foundPaymentWalletKeywords,
    foundGovernmentKeywords,
    foundTelecomUtilityKeywords,
    foundDeliveryKeywords,
    foundPlatformAccountKeywords,
    foundJobCharityFeeKeywords,
    foundTechSupportKeywords,
    foundPopupAbuseKeywords,
    foundFakeShoppingKeywords,
    foundPrizeKeywords,
    foundPiratedKeywords,
    domainCategorySignals,
    dataLeakSignals,
    securitySignals,
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
    deceptiveLowFrictionContent: Boolean(raw.deceptiveLowFrictionContent),
    formValueReadIndicator: Boolean(raw.formValueReadIndicator),
    formDataReadIndicator: Boolean(raw.formDataReadIndicator),
    sensitiveStorageWriteIndicator: Boolean(raw.sensitiveStorageWriteIndicator),
    cookieReadIndicator: Boolean(raw.cookieReadIndicator),
    encodedPayloadIndicator: Boolean(raw.encodedPayloadIndicator),
    webSocketSendIndicator: Boolean(raw.webSocketSendIndicator),
    wildcardPostMessageIndicator: Boolean(raw.wildcardPostMessageIndicator)
  };
}

function normalizeSecuritySignals(value) {
  const raw = value && typeof value === "object" ? value : {};
  return {
    responseHeadersObserved: Boolean(raw.responseHeadersObserved),
    hasContentSecurityPolicy: Boolean(raw.hasContentSecurityPolicy),
    hasStrictTransportSecurity: Boolean(raw.hasStrictTransportSecurity),
    hasXContentTypeOptions: Boolean(raw.hasXContentTypeOptions),
    hasReferrerPolicy: Boolean(raw.hasReferrerPolicy),
    hasPermissionsPolicy: Boolean(raw.hasPermissionsPolicy),
    missingSecurityHeaderCount: Number(raw.missingSecurityHeaderCount) || 0,
    mixedContentRequestCount: Number(raw.mixedContentRequestCount) || 0,
    insecureActiveContentRequestCount: Number(raw.insecureActiveContentRequestCount) || 0,
    thirdPartyScriptWithoutIntegrityCount: Number(raw.thirdPartyScriptWithoutIntegrityCount) || 0,
    unsandboxedThirdPartyIframeCount: Number(raw.unsandboxedThirdPartyIframeCount) || 0
  };
}

function normalizeUrlLexicalSignals(value) {
  const raw = value && typeof value === "object" ? value : {};
  return {
    urlLength: Number(raw.urlLength) || 0,
    domainLength: Number(raw.domainLength) || 0,
    isDomainIP: Boolean(raw.isDomainIP),
    subdomainCount: Number(raw.subdomainCount) || 0,
    excessiveSubdomainCount: Number(raw.excessiveSubdomainCount) || 0,
    hasObfuscation: Boolean(raw.hasObfuscation),
    obfuscatedCharCount: Number(raw.obfuscatedCharCount) || 0,
    domainDigitRatio: Math.max(0, Math.min(1, Number(raw.domainDigitRatio) || 0)),
    hyphenCount: Number(raw.hyphenCount) || 0,
    credentialPathWordCount: Number(raw.credentialPathWordCount) || 0,
    hasAtSymbol: Boolean(raw.hasAtSymbol),
    lexicalRiskCount: Number(raw.lexicalRiskCount) || 0
  };
}

function mergeSecuritySignals(staticSignals, observedSignals) {
  const page = normalizeSecuritySignals(staticSignals);
  const observed = normalizeSecuritySignals(observedSignals);
  return {
    responseHeadersObserved: observed.responseHeadersObserved || page.responseHeadersObserved,
    hasContentSecurityPolicy: observed.hasContentSecurityPolicy || page.hasContentSecurityPolicy,
    hasStrictTransportSecurity: observed.hasStrictTransportSecurity || page.hasStrictTransportSecurity,
    hasXContentTypeOptions: observed.hasXContentTypeOptions || page.hasXContentTypeOptions,
    hasReferrerPolicy: observed.hasReferrerPolicy || page.hasReferrerPolicy,
    hasPermissionsPolicy: observed.hasPermissionsPolicy || page.hasPermissionsPolicy,
    missingSecurityHeaderCount: observed.responseHeadersObserved ? observed.missingSecurityHeaderCount : page.missingSecurityHeaderCount,
    mixedContentRequestCount: Math.max(page.mixedContentRequestCount, observed.mixedContentRequestCount),
    insecureActiveContentRequestCount: Math.max(page.insecureActiveContentRequestCount, observed.insecureActiveContentRequestCount),
    thirdPartyScriptWithoutIntegrityCount: page.thirdPartyScriptWithoutIntegrityCount,
    unsandboxedThirdPartyIframeCount: page.unsandboxedThirdPartyIframeCount
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
  // The modular engine is the single scoring authority. Load failure is handled
  // fail-closed in handlePageScan (engine-unavailable result), so this is only
  // reached when the engine is present.
  return ArgusEngine.evaluate(signals, categoryConfig, detectionPolicy);
}

async function saveScanResult(scanResult) {
  const current = await chrome.storage.local.get(["argusTabScans"]);
  const argusTabScans = current.argusTabScans || {};

  if (Number.isInteger(scanResult.tabId) && scanResult.tabId >= 0) {
    const key = String(scanResult.tabId);
    // Monotonic write: never let a late/lower-completeness scan (e.g. a slow
    // PRELIMINARY resolving after INTERACTION_FINAL) overwrite the better result
    // for the same page. A new page load always replaces.
    if (!ArgusScanFreshness.shouldReplaceStoredScan(argusTabScans[key], scanResult)) {
      return;
    }
    argusTabScans[key] = scanResult;
  }

  await chrome.storage.local.set({
    lastArgusScan: scanResult,
    argusTabScans
  });
}

async function getLatestScan(tabId) {
  const stored = await chrome.storage.local.get(["lastArgusScan", "argusTabScans"]);
  const tabScans = stored.argusTabScans || {};

  if (Number.isInteger(tabId) && tabId >= 0) {
    return tabScans[String(tabId)] || null;
  }

  return stored.lastArgusScan || null;
}

async function clearLastScan(tabId) {
  const stored = await chrome.storage.local.get(["lastArgusScan", "argusTabScans"]);
  const tabScans = stored.argusTabScans || {};

  if (Number.isInteger(tabId) && tabId >= 0 && tabScans[String(tabId)]) {
    delete tabScans[String(tabId)];
  }

  await chrome.storage.local.set({ argusTabScans: tabScans });
  if (!Number.isInteger(tabId) || tabId < 0 || stored.lastArgusScan && stored.lastArgusScan.tabId === tabId) {
    await chrome.storage.local.remove(["lastArgusScan"]);
  }
}

async function saveFalsePositiveReport(payload) {
  const settings = await loadSettings();
  const report = sanitizeFalsePositiveReport(payload);
  report.delivery = { status: "LOCAL_ONLY", attempts: 0, lastAttemptAt: null };

  // Durability first: persist locally BEFORE any network attempt, so a delivery
  // that is blocked (Private Network Access), offline, or interrupted by a
  // service-worker shutdown can never lose the report (F17).
  await persistFalsePositiveReport(report);

  const endpoint = settings.feedbackEndpoint;
  // Deliver only to the local loopback collector (F16 pins the endpoint; re-check
  // here as defense in depth so a report is never posted off-device).
  if (settings.sendFalsePositiveFeedback && isLoopbackHost(hostnameOf(endpoint))) {
    report.delivery = { status: "QUEUED", attempts: 1, lastAttemptAt: new Date().toISOString() };
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report)
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      report.delivery.status = "SENT";
    } catch (error) {
      report.delivery.status = "QUEUED";
      report.delivery.error = describeDeliveryError(error);
    }
    await updateFalsePositiveDelivery(report.reportId, report.delivery);
  }
  return { reportId: report.reportId, delivery: report.delivery };
}

async function persistFalsePositiveReport(report) {
  const stored = await chrome.storage.local.get(["falsePositiveReports"]);
  const reports = stored.falsePositiveReports || [];
  reports.push(report);
  await chrome.storage.local.set({ falsePositiveReports: reports.slice(-5000) });
}

async function updateFalsePositiveDelivery(reportId, delivery) {
  const stored = await chrome.storage.local.get(["falsePositiveReports"]);
  const reports = stored.falsePositiveReports || [];
  const target = reports.find((item) => item && item.reportId === reportId);
  if (target) {
    target.delivery = delivery;
    await chrome.storage.local.set({ falsePositiveReports: reports });
  }
}

function hostnameOf(endpoint) {
  try {
    return new URL(String(endpoint)).hostname;
  } catch (error) {
    return "";
  }
}

function describeDeliveryError(error) {
  const message = String(error && error.message || error).slice(0, 160);
  // Chrome blocks requests from a public page context to a loopback address under
  // Private Network Access; treat that and generic network failures as a plain
  // reachability note (the report is already stored locally) rather than an error.
  if (/NETWORK_ACCESS_DENIED|Failed to fetch|private network|network error|load failed/i.test(message)) {
    return "LOCAL_COLLECTOR_UNREACHABLE (offline or blocked by Private Network Access); report stored locally.";
  }
  return message;
}

function sanitizeFalsePositiveReport(payload) {
  const raw = payload && typeof payload === "object" ? payload : {};
  const risk = raw.risk && typeof raw.risk === "object" ? raw.risk : raw;

  return {
    reportId: crypto.randomUUID(),
    reportSchemaVersion: REPORT_SCHEMA_VERSION,
    userLabel: "FALSE_POSITIVE_UNREVIEWED",
    domain: String(raw.domain || "").slice(0, 180),
    score: Math.max(0, Math.min(100, Math.round(Number(risk.score ?? risk.riskScore) || 0))),
    level: String(risk.level || "UNKNOWN").slice(0, 40),
    category: String(risk.category || "UNKNOWN").slice(0, 80),
    reasons: toArray(risk.reasons).slice(0, 8).map((reason) => String(reason).slice(0, 240)),
    timestamp: String(raw.timestamp || new Date().toISOString()),
    decisionTier: String(risk.decisionTier || "UNKNOWN").slice(0, 60),
    policyVersion: String(risk.policyVersion || "unknown").slice(0, 40),
    detectionPolicyVersion: String(risk.detectionPolicyVersion || raw.detectionPolicyVersion || "unknown").slice(0, 40),
    source: String(risk.source || raw.source || "LOCAL_MODEL").slice(0, 60),
    scoreBeforePolicy: Math.max(0, Math.min(100, Math.round(Number(risk.legacyScore) || 0))),
    scoreAfterPolicy: Math.max(0, Math.min(100, Math.round(Number(risk.score) || 0))),
    finalStatus: String(risk.status || risk.level || "UNKNOWN").slice(0, 40),
    riskContext: String(risk.riskContext || "UNKNOWN").slice(0, 60),
    warningStage: String(risk.warningStage || "NONE").slice(0, 30),
    sensitivityMode: String(risk.sensitivityMode || "BALANCED").slice(0, 30),
    claimedBrandIds: toArray(risk.claimedBrands).slice(0, 5).map((brand) => String(brand && brand.brandId || "").slice(0, 80)).filter(Boolean),
    identityEvidence: risk.identityEvidence && typeof risk.identityEvidence === "object" ? {
      domainMismatch: Boolean(risk.identityEvidence.domainMismatch),
      visualMatch: Boolean(risk.identityEvidence.visualMatch),
      deceptiveSubdomain: Boolean(risk.identityEvidence.deceptiveSubdomain),
      homographOrTyposquat: Boolean(risk.identityEvidence.homographOrTyposquat),
      lookalikeKind: String(risk.identityEvidence.lookalikeKind || "NONE").slice(0, 20)
    } : {},
    evidenceIds: toArray(risk.evidenceIds).slice(0, 30).map((id) => String(id).slice(0, 80)),
    evidenceGroups: toArray(risk.evidenceGroups).slice(0, 15).map((id) => String(id).slice(0, 80)),
    modelScore: Math.max(0, Math.min(100, Math.round(Number(risk.model && risk.model.score || risk.modelAnalysis && risk.modelAnalysis.score) || 0))),
    modelOnly: Boolean(risk.modelOnly),
    warningAllowed: Boolean(risk.warningAllowed),
    overlayAllowed: Boolean(risk.overlayAllowed),
    scanPhase: String(raw.scanPhase || "UNKNOWN").slice(0, 40),
    navigationId: String(raw.navigationId || "unknown").slice(0, 100),
    frameId: Number(raw.frameId) || 0,
    featureVector: typeof ArgusFeatureExtractor !== "undefined" ? ArgusFeatureExtractor.extract(raw) : {},
    destinationRoles: Object.keys(raw.networkSignals && raw.networkSignals.destinationRoleCounts || {}).slice(0, 30),
    reputation: raw.reputation && typeof raw.reputation === "object" ? {
      verdict: String(raw.reputation.verdict || "UNAVAILABLE").slice(0, 40),
      confidence: String(raw.reputation.confidence || "LOW").slice(0, 20),
      sources: toArray(raw.reputation.sources).slice(0, 8).map((item) => String(item).slice(0, 80)),
      categories: toArray(raw.reputation.categories).slice(0, 8).map((item) => String(item).slice(0, 80))
    } : { verdict: "UNAVAILABLE", confidence: "LOW", sources: [], categories: [] },
    interactionTimeline: sanitizeFeedbackTimeline(raw.interactionTimeline),
    shadowComparison: sanitizeFeedbackShadow(raw.shadowComparison),
    popularDomainContext: raw.popularDomainContext && raw.popularDomainContext.matched ? {
      matched: true,
      rank: Number(raw.popularDomainContext.rank) || null,
      tier: String(raw.popularDomainContext.tier || "POPULAR").slice(0, 40),
      roleHint: String(raw.popularDomainContext.roleHint || "UNKNOWN").slice(0, 60)
    } : { matched: false },
    reviewRequired: true,
    poisoningRiskNote: "User labels must be reviewed before retraining.",
    privacy: "No form values, cookies, request bodies, query strings, authorization headers, clipboard contents, file contents, passwords, or OTPs collected."
  };
}

function sanitizeFeedbackTimeline(value) {
  return toArray(value).slice(-40).map((item) => ({
    navigationId: String(item.navigationId || "").slice(0, 100), frameId: Number(item.frameId) || 0,
    timestamp: String(item.timestamp || "").slice(0, 40), eventType: String(item.eventType || "").slice(0, 60),
    scanPhase: String(item.scanPhase || "").slice(0, 40), destinationRole: String(item.destinationRole || "NONE").slice(0, 60),
    method: String(item.method || "NONE").slice(0, 12), protocol: String(item.protocol || "NONE").slice(0, 12),
    sensitiveContextPresent: Boolean(item.sensitiveContextPresent), evidenceIds: toArray(item.evidenceIds).slice(0, 8).map(String)
  }));
}

function sanitizeFeedbackShadow(value) {
  if (!value || typeof value !== "object") return null;
  return {
    legacyStatus: String(value.legacyStatus || "").slice(0, 40), legacyScore: Number(value.legacyScore) || 0,
    evidenceFirstStatus: String(value.evidenceFirstStatus || "").slice(0, 40), evidenceFirstScore: Number(value.evidenceFirstScore) || 0,
    modelScore: Number(value.modelScore) || 0, modelOnly: Boolean(value.modelOnly), overlayAllowed: Boolean(value.overlayAllowed),
    modelVersion: String(value.modelVersion || "").slice(0, 40), policyVersion: String(value.policyVersion || "").slice(0, 40)
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
  const searchDomains = SHARED_LISTS.SEARCH_ENGINE_DOMAINS || [];

  if (!searchDomains.some((candidate) => isDomainMatch(domain, candidate)) && !isGoogleDomain(domain)) {
    return false;
  }

  if (isGoogleDomain(domain) || domain.includes("bing.") || domain === "search.brave.com") {
    return pathname === "/search";
  }

  return domain.includes("duckduckgo.com") && (pathname === "/" || pathname === "/html" || pathname === "/lite");
}

function getSuspiciousDomainSignals(domain) {
  return (SHARED_LISTS.SUSPICIOUS_DOMAIN_WORDS || [])
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
