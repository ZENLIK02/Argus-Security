const SETTINGS_KEY = "argusSettings";

const DEFAULT_SETTINGS = {
  warningThreshold: 35,
  showBadgeOnSafePages: true,
  demoMode: true
};

const elements = {
  warningThreshold: document.getElementById("warningThreshold"),
  showBadgeOnSafePages: document.getElementById("showBadgeOnSafePages"),
  demoMode: document.getElementById("demoMode"),
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
}

async function saveSettings() {
  const settings = normalizeSettings({
    warningThreshold: elements.warningThreshold.value,
    showBadgeOnSafePages: elements.showBadgeOnSafePages.checked,
    demoMode: elements.demoMode.checked
  });

  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  renderSettings(settings);
  showStatus("Options saved. Reload or refresh open tabs to apply content-script display changes.");
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
    demoMode: raw.demoMode !== false
  };
}

function showStatus(message) {
  elements.status.textContent = message;
  window.setTimeout(() => {
    if (elements.status.textContent === message) {
      elements.status.textContent = "";
    }
  }, 3500);
}
