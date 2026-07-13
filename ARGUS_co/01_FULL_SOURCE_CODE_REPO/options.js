const SETTINGS_KEY = "argusSettings";

const DEFAULT_SETTINGS = {
  warningThreshold: 35,
  showBadgeOnSafePages: true,
  demoMode: true,
  progressiveScan: true,
  observationWindowMs: 4000,
  sendFalsePositiveFeedback: true,
  feedbackEndpoint: "http://localhost:8000/feedback/false-positive",
  reputationEnabled: true,
  reputationEndpoint: "http://localhost:8000/v1/reputation/check",
  sensitivityMode: "BALANCED",
  shadowMode: true
};

const elements = {
  warningThreshold: document.getElementById("warningThreshold"),
  showBadgeOnSafePages: document.getElementById("showBadgeOnSafePages"),
  demoMode: document.getElementById("demoMode"),
  progressiveScan: document.getElementById("progressiveScan"),
  observationWindowMs: document.getElementById("observationWindowMs"),
  sendFalsePositiveFeedback: document.getElementById("sendFalsePositiveFeedback"),
  feedbackEndpoint: document.getElementById("feedbackEndpoint"),
  reputationEnabled: document.getElementById("reputationEnabled"),
  reputationEndpoint: document.getElementById("reputationEndpoint"),
  sensitivityMode: document.getElementById("sensitivityMode"),
  shadowMode: document.getElementById("shadowMode"),
  save: document.getElementById("save"),
  reset: document.getElementById("reset"),
  status: document.getElementById("status")
};

initOptions();

async function initOptions() {
  const settings = await loadSettings();
  renderSettings(settings);
  elements.save.addEventListener("click", saveSettings);
  elements.reset.addEventListener("click", resetSettings);
}

async function loadSettings() {
  const stored = await chrome.storage.local.get([SETTINGS_KEY]);
  return normalizeSettings(stored[SETTINGS_KEY]);
}

function renderSettings(settings) {
  elements.warningThreshold.value = settings.warningThreshold;
  elements.showBadgeOnSafePages.checked = settings.showBadgeOnSafePages;
  elements.demoMode.checked = settings.demoMode;
  elements.progressiveScan.checked = settings.progressiveScan;
  elements.observationWindowMs.value = settings.observationWindowMs;
  elements.sendFalsePositiveFeedback.checked = settings.sendFalsePositiveFeedback;
  elements.feedbackEndpoint.value = settings.feedbackEndpoint;
  elements.reputationEnabled.checked = settings.reputationEnabled;
  elements.reputationEndpoint.value = settings.reputationEndpoint;
  elements.sensitivityMode.value = settings.sensitivityMode;
  elements.shadowMode.checked = settings.shadowMode;
}

async function saveSettings() {
  const settings = normalizeSettings({
    warningThreshold: elements.warningThreshold.value,
    showBadgeOnSafePages: elements.showBadgeOnSafePages.checked,
    demoMode: elements.demoMode.checked,
    progressiveScan: elements.progressiveScan.checked,
    observationWindowMs: elements.observationWindowMs.value,
    sendFalsePositiveFeedback: elements.sendFalsePositiveFeedback.checked,
    feedbackEndpoint: elements.feedbackEndpoint.value,
    reputationEnabled: elements.reputationEnabled.checked,
    reputationEndpoint: elements.reputationEndpoint.value,
    sensitivityMode: elements.sensitivityMode.value,
    shadowMode: elements.shadowMode.checked
  });

  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  renderSettings(settings);
  const endpointReverted = (String(elements.feedbackEndpoint.value || "").trim() &&
    settings.feedbackEndpoint !== String(elements.feedbackEndpoint.value || "").trim()) ||
    (String(elements.reputationEndpoint.value || "").trim() && settings.reputationEndpoint !== String(elements.reputationEndpoint.value || "").trim());
  showStatus(endpointReverted
    ? "Options saved. The feedback endpoint must be a local loopback address; it was reset to the local collector."
    : "Options saved. Reload or refresh open tabs to apply content-script display changes.");
}

async function resetSettings() {
  await chrome.storage.local.set({ [SETTINGS_KEY]: DEFAULT_SETTINGS });
  renderSettings(DEFAULT_SETTINGS);
  showStatus("Defaults restored.");
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
    sendFalsePositiveFeedback: raw.sendFalsePositiveFeedback !== false,
    // Loopback-only enforcement via the shared module keeps the options page and
    // the service worker in agreement (F16).
    feedbackEndpoint: ArgusFeedbackEndpoint.normalizeFeedbackEndpoint(raw.feedbackEndpoint, DEFAULT_SETTINGS.feedbackEndpoint),
    reputationEnabled: raw.reputationEnabled !== false,
    reputationEndpoint: normalizeLoopbackEndpoint(raw.reputationEndpoint, DEFAULT_SETTINGS.reputationEndpoint),
    sensitivityMode: ["CONSERVATIVE", "BALANCED", "PROTECTIVE"].includes(String(raw.sensitivityMode || "").toUpperCase()) ? String(raw.sensitivityMode).toUpperCase() : DEFAULT_SETTINGS.sensitivityMode,
    shadowMode: raw.shadowMode !== false
  };
}

function normalizeLoopbackEndpoint(value, fallback) {
  try {
    const parsed = new URL(String(value || fallback));
    return parsed.protocol === "http:" && ArgusFeedbackEndpoint.isLoopbackHost(parsed.hostname) ? parsed.toString() : fallback;
  } catch (error) {
    return fallback;
  }
}

function showStatus(message) {
  elements.status.textContent = message;
  window.setTimeout(() => {
    if (elements.status.textContent === message) {
      elements.status.textContent = "";
    }
  }, 3500);
}
