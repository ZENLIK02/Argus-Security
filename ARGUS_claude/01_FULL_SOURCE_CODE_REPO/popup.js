const GET_LATEST_MESSAGE = "ARGUS_GET_LATEST_SCAN";
const RESCAN_MESSAGE = "ARGUS_RESCAN_PAGE";
const CLEAR_LAST_SCAN_MESSAGE = "ARGUS_CLEAR_LAST_SCAN";
const REPORT_FALSE_POSITIVE_MESSAGE = "ARGUS_REPORT_FALSE_POSITIVE";

const domainEl = document.getElementById("domain");
const scoreEl = document.getElementById("score");
const levelEl = document.getElementById("level");
const categoryEl = document.getElementById("category");
const sourceEl = document.getElementById("source");
const trustedEl = document.getElementById("trusted");
const modelEl = document.getElementById("model");
const confidenceEl = document.getElementById("confidence");
const policyEl = document.getElementById("policy");
const decisionTierEl = document.getElementById("decisionTier");
const evidenceLevelEl = document.getElementById("evidenceLevel");
const warningPermissionEl = document.getElementById("warningPermission");
const guardGridEl = document.getElementById("guardGrid");
const analyzerListEl = document.getElementById("analyzerList");
const reasonsEl = document.getElementById("reasons");
const emptyEl = document.getElementById("empty");
const exportReportButton = document.getElementById("exportReport");
const openOptionsButton = document.getElementById("openOptions");
const clearScanButton = document.getElementById("clearScan");
const reportFalsePositiveButton = document.getElementById("reportFalsePositive");
const feedbackStatusEl = document.getElementById("feedbackStatus");

let activeTab = null;
let latestScan = null;

initPopup();

async function initPopup() {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  exportReportButton.addEventListener("click", exportScanReport);
  openOptionsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());
  clearScanButton.addEventListener("click", clearLastScan);
  reportFalsePositiveButton.addEventListener("click", reportFalsePositive);

  if (activeTab && activeTab.url) {
    domainEl.textContent = getDomain(activeTab.url);
  }

  const rescanRequestedAt = Date.now();
  const rescanSent = activeTab ? await requestPageRescan(activeTab.id) : false;
  const response = await getFreshLatestScan(activeTab, rescanSent ? rescanRequestedAt : 0);

  if (!response || !response.ok || !response.result) {
    showEmptyState(activeTab);
    return;
  }

  renderScan(response.result);
}

function requestPageRescan(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) {
    return Promise.resolve(false);
  }

  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, { type: RESCAN_MESSAGE }, () => {
      resolve(!chrome.runtime.lastError);
    });
  });
}

async function getFreshLatestScan(tab, minimumTimestamp) {
  let latestMatchingResponse = null;
  let bestFinalResponse = null;
  let previousSignature = "";
  let stableReadCount = 0;
  // Wait for a settled FINAL/INTERACTION_FINAL scan so the popup does not show an
  // OBSERVING/preliminary score. The interaction-final scan can land a few seconds
  // after load, so poll up to ~3s before falling back to the best available scan.
  for (let attempt = 0; attempt < 24; attempt += 1) {
    const response = await chrome.runtime.sendMessage({
      type: GET_LATEST_MESSAGE,
      tabId: tab ? tab.id : null
    });
    if (response && response.ok && response.result && scanMatchesTab(response.result, tab)) {
      latestMatchingResponse = response;
      const result = response.result;
      if (result.isFinal === true) {
        bestFinalResponse = response;
        const scanTimestamp = Date.parse(result.timestamp || "");
        const freshEnough = !minimumTimestamp || (Number.isFinite(scanTimestamp) && scanTimestamp >= minimumTimestamp);
        const risk = result.risk || {};
        const signature = [result.timestamp, result.navigationId, result.scanPhase, risk.status || risk.level, risk.score ?? risk.riskScore].join("|");
        stableReadCount = signature === previousSignature ? stableReadCount + 1 : 1;
        previousSignature = signature;
        // Settle on a stable final result once it is fresh, or after giving the
        // rescan ~1s to produce one.
        if (stableReadCount >= 3 && (freshEnough || attempt >= 8)) {
          return response;
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 125));
  }
  return bestFinalResponse || latestMatchingResponse;
}

function scanMatchesTab(scan, tab) {
  if (!scan || !tab || !tab.url) return Boolean(scan);
  // Route-accurate identity (matches SPA hash/query routes via pageKey).
  return ArgusScanFreshness.scanMatchesTab(scan, tab.url);
}

function showEmptyState(tab) {
  latestScan = null;
  scoreEl.textContent = "--";
  levelEl.textContent = "No scan";
  levelEl.className = "";
  categoryEl.textContent = "Category: unknown";
  sourceEl.textContent = "Source: none yet";
  trustedEl.textContent = "Trusted domain: unknown";
  modelEl.textContent = "Model: local only";
  confidenceEl.textContent = "Confidence: unknown";
  policyEl.textContent = "Policy: unknown";
  decisionTierEl.textContent = "Decision tier: unknown";
  evidenceLevelEl.textContent = "Evidence level: unknown";
  warningPermissionEl.textContent = "Warning permission: none";
  renderDataLeakGuard(null);
  renderAnalyzerResults(null);
  reasonsEl.replaceChildren();
  emptyEl.hidden = false;
  exportReportButton.disabled = true;
  clearScanButton.disabled = true;
  reportFalsePositiveButton.disabled = true;

  if (tab && tab.url) {
    domainEl.textContent = getDomain(tab.url);
  }
}

function renderScan(scan) {
  latestScan = scan;
  const risk = scan.risk || { score: 0, level: "SAFE", category: "SAFE", reasons: [] };
  const riskClass = getRiskClass(risk.level);
  const score = getRiskScore(risk);
  const observing = scan.isFinal === false;

  emptyEl.hidden = true;
  exportReportButton.disabled = false;
  clearScanButton.disabled = false;
  reportFalsePositiveButton.disabled = false;
  domainEl.textContent = scan.domain || getDomain(scan.url || "");
  scoreEl.textContent = observing ? "--/100" : `${score}/100`;
  scoreEl.className = observing ? "" : riskClass;
  levelEl.textContent = observing ? "OBSERVING" : formatRiskLevel(risk.level);
  levelEl.className = observing ? "" : riskClass;
  categoryEl.textContent = observing ? "Category: waiting for final result" : `Category: ${risk.category || "UNKNOWN"}`;
  sourceEl.textContent = `Source: ${risk.source || scan.source || "LOCAL_RULE_ENGINE"}`;
  trustedEl.textContent = `Trusted domain: ${scan.isTrustedDomain ? "true" : "false"}`;
  modelEl.textContent = `Model: ${getModelStatus(scan.modelStatus, risk.modelAnalysis)}`;
  confidenceEl.textContent = `Confidence: ${formatConfidence(risk.confidence)}`;
  policyEl.textContent = `Policy: ${risk.policyVersion || "legacy"}`;
  decisionTierEl.textContent = `Decision tier: ${formatDecisionTier(risk.decisionTier)}`;
  evidenceLevelEl.textContent = `Evidence level: ${risk.evidenceLevel || "NONE"}`;
  warningPermissionEl.textContent = `Warning permission: ${risk.warningAllowed ? "badge/details only" : "none"}`;
  renderDataLeakGuard(scan);
  renderAnalyzerResults(scan);

  reasonsEl.replaceChildren();
  (risk.reasons || ["No detailed reasons were returned."]).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsEl.appendChild(item);
  });
}

async function reportFalsePositive() {
  if (!latestScan) return;
  feedbackStatusEl.textContent = "Saving feedback...";
  const response = await chrome.runtime.sendMessage({ type: REPORT_FALSE_POSITIVE_MESSAGE, payload: latestScan });
  const status = response && response.result && response.result.delivery && response.result.delivery.status;
  feedbackStatusEl.textContent = status === "SENT"
    ? "Saved and sent to the local feedback collector."
    : "Saved locally and queued until the feedback collector is online.";
}

function exportScanReport() {
  if (!latestScan) {
    return;
  }

  const risk = latestScan.risk || {};
  const report = {
    reportSchemaVersion: latestScan.reportSchemaVersion || "2",
    timestamp: new Date().toISOString(),
    scanTimestamp: latestScan.timestamp || null,
    url: latestScan.url || "",
    domain: latestScan.domain || "",
    isTrustedDomain: Boolean(latestScan.isTrustedDomain),
    isSearchEnginePage: Boolean(latestScan.isSearchEnginePage),
    finalRiskScore: getRiskScore(risk),
    finalRiskLevel: risk.level || "UNKNOWN",
    category: risk.category || "UNKNOWN",
    source: risk.source || latestScan.source || "UNKNOWN",
    reasons: Array.isArray(risk.reasons) ? risk.reasons : [],
    confidence: normalizeConfidence(risk.confidence),
    policyVersion: risk.policyVersion || null,
    detectionPolicyVersion: risk.detectionPolicyVersion || latestScan.detectionPolicyVersion || null,
    decisionTier: risk.decisionTier || "UNKNOWN",
    finalStatus: risk.status || risk.level || "UNKNOWN",
    scoreBeforePolicy: Number(risk.legacyScore) || 0,
    scoreAfterPolicy: getRiskScore(risk),
    evidenceLevel: risk.evidenceLevel || "NONE",
    evidenceIds: Array.isArray(risk.evidenceIds) ? risk.evidenceIds : [],
    evidenceGroups: Array.isArray(risk.evidenceGroups) ? risk.evidenceGroups : [],
    directEvidence: sanitizeDirectEvidence(risk.directEvidence),
    modelOnly: Boolean(risk.modelOnly),
    warningAllowed: Boolean(risk.warningAllowed),
    overlayAllowed: Boolean(risk.overlayAllowed),
    navigationId: latestScan.navigationId || null,
    frameId: Number(latestScan.frameId) || 0,
    scanPhase: latestScan.scanPhase || "UNKNOWN",
    interactionTimeline: sanitizeTimeline(latestScan.interactionTimeline),
    shadowComparison: sanitizeShadowComparison(latestScan.shadowComparison),
    evidence: sanitizeEvidence(risk.evidence),
    toolResults: sanitizeToolResults(risk.toolResults),
    modelAnalysis: sanitizeModelAnalysis(risk.modelAnalysis),
    modelStatus: latestScan.modelStatus || { mode: "LOCAL_RULE_ENGINE", externalAi: false },
    dataLeakSignals: sanitizeDataLeakSignals(latestScan.dataLeakSignals),
    networkSignals: sanitizeNetworkSignals(latestScan.networkSignals),
    securitySignals: sanitizeSecuritySignals(latestScan.securitySignals),
    urlLexicalSignals: sanitizeUrlLexicalSignals(latestScan.urlLexicalSignals)
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = buildReportFilename(report);
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}

function sanitizeDirectEvidence(value) {
  return (Array.isArray(value) ? value : []).slice(0, 12).map((item) => ({
    id: String(item.id || ""), type: String(item.type || ""), severity: String(item.severity || ""),
    timestamp: String(item.timestamp || ""), source: String(item.source || ""),
    destinationRole: String(item.destinationRole || "UNKNOWN"), navigationId: String(item.navigationId || ""),
    frameId: Number(item.frameId) || 0, scanPhase: String(item.scanPhase || ""), explanation: String(item.explanation || "")
  }));
}

function sanitizeTimeline(value) {
  return (Array.isArray(value) ? value : []).slice(-40).map((item) => ({
    navigationId: String(item.navigationId || ""), frameId: Number(item.frameId) || 0,
    timestamp: String(item.timestamp || ""), eventType: String(item.eventType || ""),
    scanPhase: String(item.scanPhase || ""), destinationRole: String(item.destinationRole || "NONE"),
    method: String(item.method || "NONE"), protocol: String(item.protocol || "NONE"),
    sensitiveContextPresent: Boolean(item.sensitiveContextPresent),
    evidenceIds: Array.isArray(item.evidenceIds) ? item.evidenceIds.slice(0, 8).map(String) : []
  }));
}

function sanitizeShadowComparison(value) {
  if (!value || typeof value !== "object") return null;
  return {
    legacyStatus: String(value.legacyStatus || ""), legacyScore: Number(value.legacyScore) || 0,
    evidenceFirstStatus: String(value.evidenceFirstStatus || ""), evidenceFirstScore: Number(value.evidenceFirstScore) || 0,
    evidenceIds: Array.isArray(value.evidenceIds) ? value.evidenceIds.slice(0, 20).map(String) : [],
    modelScore: Number(value.modelScore) || 0, modelOnly: Boolean(value.modelOnly),
    overlayAllowed: Boolean(value.overlayAllowed), timestamp: String(value.timestamp || ""),
    modelVersion: String(value.modelVersion || ""), policyVersion: String(value.policyVersion || "")
  };
}

function renderAnalyzerResults(scan) {
  const tools = scan && scan.risk && Array.isArray(scan.risk.toolResults) ? scan.risk.toolResults : [];
  analyzerListEl.replaceChildren();

  if (tools.length === 0) {
    const empty = document.createElement("div");
    empty.className = "analyzer-item";
    empty.textContent = "No analyzer results yet";
    analyzerListEl.appendChild(empty);
    return;
  }

  tools.forEach((result) => {
    const item = document.createElement("div");
    item.className = "analyzer-item";
    item.dataset.status = result.status || "CLEAR";

    const name = document.createElement("strong");
    name.textContent = formatToolName(result.tool);
    item.appendChild(name);

    const score = document.createElement("span");
    score.textContent = `${Number(result.score) || 0}/100`;
    item.appendChild(score);

    const status = document.createElement("span");
    status.textContent = `${result.status || "CLEAR"} · ${Number(result.findingCount) || 0} finding(s)`;
    item.appendChild(status);

    const confidence = document.createElement("span");
    confidence.textContent = formatConfidence(result.confidence);
    item.appendChild(confidence);

    analyzerListEl.appendChild(item);
  });
}

function formatToolName(value) {
  return String(value || "ANALYZER")
    .replace(/_ANALYZER$/g, "")
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function normalizeConfidence(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(1, number)) : null;
}

function formatConfidence(value) {
  const normalized = normalizeConfidence(value);
  return normalized === null ? "unknown" : `${Math.round(normalized * 100)}%`;
}

function formatDecisionTier(value) {
  const labels = {
    OBSERVED_DATA_FLOW: "1 - observed data flow",
    CONTEXT_OR_INTENT: "2 - context or intent",
    CONTENT_CATEGORY: "3 - content category",
    NO_FINDINGS: "none"
  };
  return labels[value] || "unknown";
}

function sanitizeEvidence(value) {
  return Array.isArray(value) ? value.slice(0, 30).map((item) => ({
    id: String(item.id || "").slice(0, 80),
    tool: String(item.tool || "").slice(0, 80),
    category: String(item.category || "").slice(0, 80),
    priority: Math.max(1, Math.min(3, Number(item.priority) || 3)),
    points: Number(item.points) || 0,
    confidence: normalizeConfidence(item.confidence),
    severity: String(item.severity || "").slice(0, 20),
    message: String(item.message || "").slice(0, 240),
    decisive: Boolean(item.decisive)
  })) : [];
}

function sanitizeToolResults(value) {
  return Array.isArray(value) ? value.slice(0, 12).map((item) => ({
    tool: String(item.tool || "").slice(0, 80),
    score: Number(item.score) || 0,
    confidence: normalizeConfidence(item.confidence),
    status: String(item.status || "CLEAR").slice(0, 20),
    findingCount: Number(item.findingCount) || 0,
    topEvidence: Array.isArray(item.topEvidence) ? item.topEvidence.slice(0, 3).map((message) => String(message).slice(0, 240)) : []
  })) : [];
}

async function clearLastScan() {
  await chrome.runtime.sendMessage({
    type: CLEAR_LAST_SCAN_MESSAGE,
    tabId: activeTab ? activeTab.id : null
  });
  showEmptyState(activeTab);
}

function buildReportFilename(report) {
  const safeDomain = String(report.domain || "unknown").replace(/[^a-z0-9.-]+/gi, "-").slice(0, 80);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `project-argus-scan-${safeDomain}-${stamp}.json`;
}

function renderDataLeakGuard(scan) {
  const dataLeak = scan && scan.dataLeakSignals ? scan.dataLeakSignals : {};
  const network = scan && scan.networkSignals ? scan.networkSignals : {};
  const security = scan && scan.securitySignals ? scan.securitySignals : {};
  const lexical = scan && scan.urlLexicalSignals ? scan.urlLexicalSignals : {};
  const items = [
    ["Cross-domain forms", dataLeak.crossDomainFormActionCount],
    ["HTTP form actions", dataLeak.httpFormActionCount],
    ["Sensitive forms", dataLeak.sensitiveFormCount],
    ["Hidden iframes", dataLeak.hiddenIframeCount],
    ["External scripts", dataLeak.externalScriptCount],
    ["Third-party requests", network.thirdPartyRequests],
    ["Third-party XHR/fetch", network.thirdPartyXHRRequests],
    ["After form submit", network.requestsAfterFormSubmit],
    ["After password focus", network.requestsAfterPasswordFocus],
    ["Unencrypted sensitive writes", network.insecureSensitiveWriteRequests],
    ["Cross-domain sensitive writes", network.crossDomainSensitiveWriteRequests],
    ["Sensitive beacons/pixels", Number(network.beaconOrPingAfterSensitiveInput || 0) + Number(network.queryBearingGetAfterSensitiveForm || 0)],
    ["Form-to-third-party", network.temporalSignals && network.temporalSignals.formSubmitThenThirdPartyCount],
    ["Post-form redirects", network.temporalSignals && network.temporalSignals.formSubmitThenCrossDomainRedirectCount],
    ["Credential-like fields", dataLeak.credentialLikeTextFieldCount],
    ["Script network sinks", dataLeak.scriptNetworkSinkCount],
    ["Dynamic endpoints", dataLeak.dynamicEndpointAssemblyCount],
    ["Form/script relay", Number(Boolean(dataLeak.formValueReadIndicator)) + Number(Boolean(dataLeak.formDataReadIndicator))],
    ["Storage/cookie relay", Number(Boolean(dataLeak.sensitiveStorageWriteIndicator)) + Number(Boolean(dataLeak.cookieReadIndicator))],
    ["Mixed active content", security.insecureActiveContentRequestCount],
    ["Unprotected third-party scripts", security.thirdPartyScriptWithoutIntegrityCount],
    ["URL lexical indicators", lexical.lexicalRiskCount],
    ["Clipboard/file signals", Number(Boolean(dataLeak.clipboardReadIndicator)) + Number(Boolean(dataLeak.fileMetadataHarvestIndicator))],
    ["HTTP APK links", Array.isArray(dataLeak.httpApkLinks) ? dataLeak.httpApkLinks.length : 0],
    ["Third-party APK links", Array.isArray(dataLeak.thirdPartyApkLinks) ? dataLeak.thirdPartyApkLinks.length : 0]
  ];

  guardGridEl.replaceChildren(...items.map(([label, value]) => {
    const item = document.createElement("div");
    item.className = "guard-item";

    const labelEl = document.createElement("span");
    labelEl.textContent = label;
    item.appendChild(labelEl);

    const valueEl = document.createElement("strong");
    valueEl.textContent = String(Number(value) || 0);
    item.appendChild(valueEl);

    return item;
  }));
}

function sanitizeDataLeakSignals(signals) {
  const raw = signals || {};
  return {
    formCount: Number(raw.formCount) || 0,
    sensitiveFormCount: Number(raw.sensitiveFormCount) || 0,
    crossDomainFormActionCount: Number(raw.crossDomainFormActionCount) || 0,
    httpFormActionCount: Number(raw.httpFormActionCount) || 0,
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
    thirdPartyApkLinks: Array.isArray(raw.thirdPartyApkLinks) ? raw.thirdPartyApkLinks.slice(0, 10) : [],
    httpApkLinks: Array.isArray(raw.httpApkLinks) ? raw.httpApkLinks.slice(0, 10) : [],
    inlineScriptCount: Number(raw.inlineScriptCount) || 0,
    scriptNetworkSinkCount: Number(raw.scriptNetworkSinkCount) || 0,
    dynamicEndpointAssemblyCount: Number(raw.dynamicEndpointAssemblyCount) || 0,
    externalUrlHints: Array.isArray(raw.externalUrlHints) ? raw.externalUrlHints.slice(0, 10) : [],
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

function sanitizeNetworkSignals(signals) {
  const raw = signals || {};
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
    suspiciousRequestDomains: Array.isArray(raw.suspiciousRequestDomains) ? raw.suspiciousRequestDomains.slice(0, 20) : [],
    destinationRoles: Array.isArray(raw.destinationRoles) ? raw.destinationRoles.slice(0, 30) : [],
    destinationRoleCounts: raw.destinationRoleCounts && typeof raw.destinationRoleCounts === "object" ? { ...raw.destinationRoleCounts } : {},
    temporalSignals: {
      formSubmitThenThirdPartyCount: Number(raw.temporalSignals && raw.temporalSignals.formSubmitThenThirdPartyCount) || 0,
      passwordFocusThenThirdPartyCount: Number(raw.temporalSignals && raw.temporalSignals.passwordFocusThenThirdPartyCount) || 0,
      formSubmitThenCrossDomainRedirectCount: Number(raw.temporalSignals && raw.temporalSignals.formSubmitThenCrossDomainRedirectCount) || 0,
      downloadAfterFormSubmitCount: Number(raw.temporalSignals && raw.temporalSignals.downloadAfterFormSubmitCount) || 0,
      unencryptedSensitiveWriteCount: Number(raw.temporalSignals && raw.temporalSignals.unencryptedSensitiveWriteCount) || 0,
      crossDomainSensitiveWriteCount: Number(raw.temporalSignals && raw.temporalSignals.crossDomainSensitiveWriteCount) || 0,
      beaconAfterSensitiveInputCount: Number(raw.temporalSignals && raw.temporalSignals.beaconAfterSensitiveInputCount) || 0,
      recentEventTypes: Array.isArray(raw.temporalSignals && raw.temporalSignals.recentEventTypes) ? raw.temporalSignals.recentEventTypes.slice(-20) : []
    }
  };
}

function sanitizeModelAnalysis(value) {
  const raw = value || {};
  return {
    available: Boolean(raw.available),
    applied: Boolean(raw.applied),
    score: Number(raw.score) || 0,
    probability: Number(raw.probability) || 0,
    evidenceGroups: Number(raw.evidenceGroups) || 0,
    version: String(raw.version || "unavailable").slice(0, 40)
  };
}

function sanitizeSecuritySignals(value) {
  const raw = value || {};
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

function sanitizeUrlLexicalSignals(value) {
  const raw = value || {};
  return {
    urlLength: Number(raw.urlLength) || 0,
    domainLength: Number(raw.domainLength) || 0,
    isDomainIP: Boolean(raw.isDomainIP),
    subdomainCount: Number(raw.subdomainCount) || 0,
    excessiveSubdomainCount: Number(raw.excessiveSubdomainCount) || 0,
    hasObfuscation: Boolean(raw.hasObfuscation),
    obfuscatedCharCount: Number(raw.obfuscatedCharCount) || 0,
    domainDigitRatio: Number(raw.domainDigitRatio) || 0,
    hyphenCount: Number(raw.hyphenCount) || 0,
    credentialPathWordCount: Number(raw.credentialPathWordCount) || 0,
    hasAtSymbol: Boolean(raw.hasAtSymbol),
    lexicalRiskCount: Number(raw.lexicalRiskCount) || 0
  };
}

function getModelStatus(status, analysis) {
  if (!status || !status.mode) {
    return "Project Argus local model";
  }

  const model = analysis && analysis.available ? `, calibrator ${analysis.score}/100${analysis.applied ? " applied" : " advisory"}` : "";
  return `${status.mode}${model}`;
}

function getRiskScore(risk) {
  const rawScore = risk.score ?? risk.riskScore;
  const value = Number(rawScore);
  return Number.isFinite(value) ? Math.round(value) : "--";
}

function getRiskClass(level) {
  if (level === "HIGH RISK" || level === "HIGH_RISK") {
    return "high-risk";
  }

  if (level === "SUSPICIOUS") {
    return "suspicious";
  }
  if (level === "MONITORING" || level === "UNCERTAIN" || level === "UNAVAILABLE") {
    return "monitoring";
  }

  return "safe";
}

function formatRiskLevel(level) {
  return String(level || "SAFE").replace(/_/g, " ");
}

function getDomain(url) {
  try {
    return new URL(url).hostname || "local-file";
  } catch (error) {
    return "unknown";
  }
}
