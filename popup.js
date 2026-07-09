const GET_LATEST_MESSAGE = "ARGUS_GET_LATEST_SCAN";
const RESCAN_MESSAGE = "ARGUS_RESCAN_PAGE";
const CLEAR_LAST_SCAN_MESSAGE = "ARGUS_CLEAR_LAST_SCAN";

const domainEl = document.getElementById("domain");
const scoreEl = document.getElementById("score");
const levelEl = document.getElementById("level");
const categoryEl = document.getElementById("category");
const sourceEl = document.getElementById("source");
const trustedEl = document.getElementById("trusted");
const modelEl = document.getElementById("model");
const guardGridEl = document.getElementById("guardGrid");
const reasonsEl = document.getElementById("reasons");
const emptyEl = document.getElementById("empty");
const exportReportButton = document.getElementById("exportReport");
const openOptionsButton = document.getElementById("openOptions");
const clearScanButton = document.getElementById("clearScan");

let activeTab = null;
let latestScan = null;

initPopup();

async function initPopup() {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  exportReportButton.addEventListener("click", exportScanReport);
  openOptionsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());
  clearScanButton.addEventListener("click", clearLastScan);

  if (activeTab && activeTab.url) {
    domainEl.textContent = getDomain(activeTab.url);
    requestPageRescan(activeTab.id);
  }

  const response = await chrome.runtime.sendMessage({
    type: GET_LATEST_MESSAGE,
    tabId: activeTab ? activeTab.id : null
  });

  if (!response || !response.ok || !response.result) {
    showEmptyState(activeTab);
    return;
  }

  renderScan(response.result);
}

function requestPageRescan(tabId) {
  if (!tabId) {
    return;
  }

  chrome.tabs.sendMessage(tabId, { type: RESCAN_MESSAGE }, () => {
    chrome.runtime.lastError;
  });
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
  renderDataLeakGuard(null);
  reasonsEl.replaceChildren();
  emptyEl.hidden = false;
  exportReportButton.disabled = true;
  clearScanButton.disabled = true;

  if (tab && tab.url) {
    domainEl.textContent = getDomain(tab.url);
  }
}

function renderScan(scan) {
  latestScan = scan;
  const risk = scan.risk || { score: 0, level: "SAFE", category: "SAFE", reasons: [] };
  const riskClass = getRiskClass(risk.level);
  const score = getRiskScore(risk);

  emptyEl.hidden = true;
  exportReportButton.disabled = false;
  clearScanButton.disabled = false;
  domainEl.textContent = scan.domain || getDomain(scan.url || "");
  scoreEl.textContent = `${score}/100`;
  scoreEl.className = riskClass;
  levelEl.textContent = formatRiskLevel(risk.level);
  levelEl.className = riskClass;
  categoryEl.textContent = `Category: ${risk.category || "UNKNOWN"}`;
  sourceEl.textContent = `Source: ${risk.source || scan.source || "LOCAL_MODEL"}`;
  trustedEl.textContent = `Trusted domain: ${scan.isTrustedDomain ? "true" : "false"}`;
  modelEl.textContent = `Model: ${getModelStatus(scan.modelStatus)}`;
  renderDataLeakGuard(scan);

  reasonsEl.replaceChildren();
  (risk.reasons || ["No detailed reasons were returned."]).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsEl.appendChild(item);
  });
}

function exportScanReport() {
  if (!latestScan) {
    return;
  }

  const risk = latestScan.risk || {};
  const report = {
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
    modelStatus: latestScan.modelStatus || { mode: "LOCAL_MODEL", externalAi: false },
    dataLeakSignals: sanitizeDataLeakSignals(latestScan.dataLeakSignals),
    networkSignals: sanitizeNetworkSignals(latestScan.networkSignals)
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = buildReportFilename(report);
  anchor.click();
  URL.revokeObjectURL(objectUrl);
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
  const items = [
    ["Cross-domain forms", dataLeak.crossDomainFormActionCount],
    ["HTTP form actions", dataLeak.httpFormActionCount],
    ["Hidden iframes", dataLeak.hiddenIframeCount],
    ["External scripts", dataLeak.externalScriptCount],
    ["Third-party requests", network.thirdPartyRequests],
    ["Third-party XHR/fetch", network.thirdPartyXHRRequests],
    ["After form submit", network.requestsAfterFormSubmit],
    ["After password focus", network.requestsAfterPasswordFocus],
    ["Credential-like fields", dataLeak.credentialLikeTextFieldCount],
    ["Script network sinks", dataLeak.scriptNetworkSinkCount],
    ["Dynamic endpoints", dataLeak.dynamicEndpointAssemblyCount],
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
    crossDomainFormActionCount: Number(raw.crossDomainFormActionCount) || 0,
    httpFormActionCount: Number(raw.httpFormActionCount) || 0,
    passwordCrossDomainForm: Boolean(raw.passwordCrossDomainForm),
    otpOrPaymentCrossDomainForm: Boolean(raw.otpOrPaymentCrossDomainForm),
    passwordHttpForm: Boolean(raw.passwordHttpForm),
    otpOrPaymentHttpForm: Boolean(raw.otpOrPaymentHttpForm),
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
    deceptiveLowFrictionContent: Boolean(raw.deceptiveLowFrictionContent)
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
    requestsAfterFormSubmit: Number(raw.requestsAfterFormSubmit) || 0,
    requestsAfterPasswordFocus: Number(raw.requestsAfterPasswordFocus) || 0,
    suspiciousRequestDomains: Array.isArray(raw.suspiciousRequestDomains) ? raw.suspiciousRequestDomains.slice(0, 20) : []
  };
}

function getModelStatus(status) {
  if (!status || !status.mode) {
    return "Project Argus local model";
  }

  return status.externalAi ? status.mode : `${status.mode} only`;
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
