"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const { chromium } = require("playwright");
const EvidencePolicy = require("../engine/evidence_decision_policy.js");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DIR = path.join(ROOT, "reports", "night_autofix");
const PROFILE_DIR = path.join(REPORT_DIR, "profiles");
const ARTIFACT_DIR = path.join(REPORT_DIR, "artifacts");
const RESULTS_PATH = path.join(REPORT_DIR, "browser_results.jsonl");
const CHROME_PATH = process.env.ARGUS_CHROME_PATH || chromium.executablePath();
const DETECTION_POLICY = JSON.parse(fs.readFileSync(path.join(ROOT, "engine", "detection_policy.json"), "utf8"));
const EVIDENCE_GROUP_BY_ID = new Map();
for (const [group, ids] of Object.entries(EvidencePolicy.GROUPS)) {
  for (const id of ids) EVIDENCE_GROUP_BY_ID.set(id, group);
}

function option(name, fallback) {
  const prefix = `--${name}=`;
  const raw = process.argv.find((item) => item.startsWith(prefix));
  return raw ? raw.slice(prefix.length) : fallback;
}

function appendJsonLine(file, value) {
  fs.appendFileSync(file, `${JSON.stringify(value)}\n`, "utf8");
}

async function startFixtureServer(fixtureRoot) {
  const server = http.createServer((request, response) => {
    const requested = decodeURIComponent(new URL(request.url, "http://fixture.local").pathname).replace(/^\/+/, "");
    const file = path.resolve(fixtureRoot, requested || "safe-site.html");
    if (!file.startsWith(`${fixtureRoot}${path.sep}`) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      response.writeHead(requested.startsWith("sink/") ? 204 : 404, { "Access-Control-Allow-Origin": "*" });
      response.end();
      return;
    }
    response.writeHead(200, {
      "Content-Type": path.extname(file) === ".js" ? "application/javascript" : "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    });
    fs.createReadStream(file).pipe(response);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server;
}

function sanitizeName(value) {
  return String(value).replace(/[^a-z0-9_.-]+/gi, "-").replace(/^-|-$/g, "").slice(0, 80);
}

function parseDisplayedScore(text) {
  const match = String(text || "").match(/\d+/);
  return match ? Number(match[0]) : null;
}

function topContributors(scan) {
  const evidence = Array.isArray(scan?.risk?.evidence) ? scan.risk.evidence : [];
  const directIds = new Set((scan?.risk?.directEvidence || []).map((item) => item.id));
  const timeline = Array.isArray(scan?.interactionTimeline) ? scan.interactionTimeline : [];
  return evidence
    .map((item) => {
      const id = String(item.id || "UNKNOWN");
      const group = EVIDENCE_GROUP_BY_ID.get(id) || null;
      const behavioralEvidence = Boolean(group && group !== "SENSITIVE_INPUT");
      return {
        featureName: id,
        observedValue: 1,
        weight: Number(DETECTION_POLICY.weights?.[id] ?? 0),
        contribution: Number(item.points || 0),
        contextOnly: !directIds.has(id) && !behavioralEvidence,
        behavioralEvidence,
        evidenceIds: [id],
        eventIds: timeline.filter((event) => Array.isArray(event.evidenceIds) && event.evidenceIds.includes(id)).map((event) => String(event.eventType || event.timestamp)).slice(0, 8)
      };
    })
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 12);
}

function buildDiagnostic({ scan, popup, site, profileName, extensionId, extensionVersion, elapsedMs, browserObservedRequests }) {
  const risk = scan?.risk || {};
  const network = scan?.networkSignals || {};
  const telemetry = scan?.telemetryDiagnostics || scan?.diagnostics || {};
  const rawModelScore = Number(
    risk?.model?.score ??
    risk?.modelAnalysis?.score ??
    scan?.ruleBasedRisk?.modelAnalysis?.score ??
    scan?.shadowComparison?.modelScore ??
    0
  );
  const policyRiskScore = Number(risk.score ?? risk.riskScore ?? 0);
  const displayedScore = parseDisplayedScore(popup.scoreText);
  const topScoreContributors = Array.isArray(risk.topScoreContributors)
    ? risk.topScoreContributors
    : topContributors(scan);

  return {
    timestamp: new Date().toISOString(),
    site,
    finalUrl: popup.activeUrl,
    profileName,
    freshProfile: true,
    runner: "PLAYWRIGHT",
    popupProof: {
      url: popup.url,
      scoreTestId: "argus-policy-score",
      statusTestId: "argus-policy-status",
      scoreText: popup.scoreText,
      statusText: popup.statusText,
      domainText: popup.domainText
    },
    status: String(risk.status || risk.level || popup.statusText || "UNKNOWN"),
    rawModelScore,
    policyRiskScore,
    displayedScore,
    confidenceScore: risk.confidenceScore ?? risk.confidence ?? null,
    observationState: scan?.observationState || (scan?.isFinal === false ? "OBSERVING" : "FINAL"),
    staticContextScore: Number(risk.staticContextScore ?? scan?.ruleBasedRisk?.score ?? 0),
    behavioralEvidenceScore: Number(risk.behavioralEvidenceScore ?? 0),
    evidenceGroups: Array.isArray(risk.evidenceGroups) ? risk.evidenceGroups : [],
    directEvidence: Array.isArray(risk.directEvidence) ? risk.directEvidence : [],
    topScoreContributors,
    destinationRoleCounts: network.destinationRoleCounts || {},
    unknownDestinations: network.unknownSensitiveDestinations || network.suspiciousRequestDomains || [],
    staleEventsRejected: Number(telemetry.staleEventsRejected || 0),
    duplicateEventsRejected: Number(telemetry.duplicateEventsRejected || 0),
    telemetryDroppedEvents: Number(telemetry.telemetryDroppedEvents || 0),
    eventSequence: telemetry.eventSequence || null,
    navigationSessionId: String(scan?.navigationSessionId || scan?.navigationId || "unknown"),
    documentId: String(scan?.documentId || "unavailable"),
    tabId: Number(scan?.tabId),
    frameId: Number(scan?.frameId || 0),
    origin: (() => { try { return new URL(popup.activeUrl).origin; } catch { return "unknown"; } })(),
    extensionId,
    extensionVersion,
    policyVersion: String(scan?.policyVersion || risk.policyVersion || "unknown"),
    reportSchemaVersion: String(scan?.reportSchemaVersion || risk.reportSchemaVersion || "unknown"),
    stateResetReason: telemetry.stateResetReason || null,
    timestamps: {
      navigationStartedAt: popup.navigationStartedAt,
      scanTimestamp: scan?.timestamp || null,
      popupReadAt: new Date().toISOString(),
      elapsedMs
    },
    browserObservedRequests,
    consistentScorePath: displayedScore === policyRiskScore,
    failedAcceptance: displayedScore == null || displayedScore > 5 || ["SUSPICIOUS", "HIGH_RISK"].includes(String(risk.status || risk.level || ""))
  };
}

async function getExtensionWorker(context) {
  const existing = context.serviceWorkers().find((worker) => worker.url().startsWith("chrome-extension://"));
  if (existing) return existing;
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith("chrome-extension://"),
    timeout: 20000
  });
}

async function findSiteTab(worker, hostname) {
  return worker.evaluate(async (expectedHostname) => {
    const tabs = await chrome.tabs.query({});
    return tabs.find((tab) => {
      try { return new URL(tab.url || "").hostname === expectedHostname; }
      catch { return false; }
    }) || null;
  }, hostname);
}

async function readLatestScan(worker, tabId) {
  return worker.evaluate(async (id) => {
    const stored = await chrome.storage.local.get(["argusTabScans"]);
    return stored.argusTabScans && stored.argusTabScans[String(id)] || null;
  }, tabId);
}

async function waitForLatestScan(worker, tabId, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const scan = await readLatestScan(worker, tabId);
    if (scan && scan.isFinal !== false) return scan;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  return readLatestScan(worker, tabId);
}

async function auditSite(context, worker, extensionId, extensionVersion, site, profileName, waitMs) {
  const siteName = sanitizeName(new URL(site).hostname);
  const artifactBase = path.join(ARTIFACT_DIR, `${profileName}-${siteName}`);
  const navigationStartedAt = new Date().toISOString();
  const started = Date.now();
  const observed = new Map();
  const page = await context.newPage();
  page.on("request", (request) => {
    try {
      const url = new URL(request.url());
      const key = `${request.method()} ${url.origin}`;
      observed.set(key, (observed.get(key) || 0) + 1);
    } catch {}
  });

  let navigationError = null;
  try {
    await page.goto(site, { waitUntil: "domcontentloaded", timeout: 45000 });
  } catch (error) {
    navigationError = String(error.message || error).slice(0, 400);
  }
  await page.waitForTimeout(waitMs);
  const activeUrl = page.url();
  const hostname = new URL(activeUrl).hostname;
  const tab = await findSiteTab(worker, hostname);
  if (!tab || !Number.isInteger(tab.id)) throw new Error(`ARGUS site tab not found for ${hostname}`);

  const popupPage = await context.newPage();
  await page.bringToFront();
  await popupPage.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: "domcontentloaded", timeout: 15000 });
  await popupPage.getByTestId("argus-policy-score").waitFor({ state: "visible", timeout: 15000 });
  await popupPage.waitForFunction(() => {
    const score = document.querySelector('[data-testid="argus-policy-score"]');
    const status = document.querySelector('[data-testid="argus-policy-status"]');
    return score && status && !String(score.textContent).includes("--") && !/scanning|loading/i.test(String(status.textContent));
  }, null, { timeout: 5000 });
  const popup = {
    url: popupPage.url(),
    activeUrl,
    navigationStartedAt,
    scoreText: await popupPage.getByTestId("argus-policy-score").textContent(),
    statusText: await popupPage.getByTestId("argus-policy-status").textContent(),
    domainText: await popupPage.getByTestId("argus-domain").textContent()
  };
  const scan = await waitForLatestScan(worker, tab.id);
  if (!scan) {
    const storage = await worker.evaluate(async () => chrome.storage.local.get(["lastArgusScan", "argusTabScans"]));
    const badgeText = await page.locator("#argus-scan-badge").textContent().catch(() => null);
    throw new Error(`ARGUS returned no scan for tab ${tab.id} (${hostname}); badge=${JSON.stringify(badgeText)} storageKeys=${JSON.stringify(Object.keys(storage.argusTabScans || {}))}`);
  }

  const browserObservedRequests = Array.from(observed, ([key, count]) => ({ key, count })).slice(0, 100);
  const diagnostic = buildDiagnostic({
    scan, popup, site, profileName, extensionId, extensionVersion,
    elapsedMs: Date.now() - started, browserObservedRequests
  });
  diagnostic.navigationError = navigationError;
  if (diagnostic.failedAcceptance || !diagnostic.consistentScorePath || navigationError) {
    await popupPage.screenshot({ path: `${artifactBase}-popup.png` });
    await page.screenshot({ path: `${artifactBase}-page.png`, fullPage: false });
    fs.writeFileSync(`${artifactBase}-diagnostic.json`, JSON.stringify({ diagnostic, scan }, null, 2));
  }
  appendJsonLine(RESULTS_PATH, diagnostic);
  await popupPage.close();
  await page.close();
  return diagnostic;
}

async function main() {
  fs.mkdirSync(PROFILE_DIR, { recursive: true });
  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
  const fixtureNames = option("fixtures", "").split(",").filter(Boolean);
  const fixtureRoot = path.resolve(ROOT, option("fixture-root", "test-site"));
  if (!fixtureRoot.startsWith(`${ROOT}${path.sep}`)) throw new Error("Fixture root must remain inside the ARGUS repository.");
  let fixtureServer = null;
  let sites = option("sites", "https://www.youtube.com/,https://www.roblox.com/").split(",").filter(Boolean);
  if (fixtureNames.length) {
    fixtureServer = await startFixtureServer(fixtureRoot);
    const address = fixtureServer.address();
    sites = fixtureNames.map((name) => `http://127.0.0.1:${address.port}/${encodeURIComponent(name)}`);
  }
  const profileName = sanitizeName(option("profile", `pw-${Date.now()}`));
  const profilePath = path.join(PROFILE_DIR, profileName);
  const waitMs = Math.max(4000, Math.min(20000, Number(option("wait-ms", "8000")) || 8000));
  if (fs.existsSync(profilePath)) throw new Error(`Refusing non-fresh profile: ${profilePath}`);

  const context = await chromium.launchPersistentContext(profilePath, {
    executablePath: CHROME_PATH,
    headless: true,
    viewport: { width: 1365, height: 900 },
    acceptDownloads: false,
    args: [
      `--disable-extensions-except=${ROOT}`,
      `--load-extension=${ROOT}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-sync",
      "--disable-background-mode"
    ]
  });

  try {
    const worker = await getExtensionWorker(context);
    const extensionId = new URL(worker.url()).hostname;
    const extensionVersion = await worker.evaluate(() => chrome.runtime.getManifest().version);
    const results = [];
    for (const site of sites) {
      results.push(await auditSite(context, worker, extensionId, extensionVersion, site, profileName, waitMs));
    }
    process.stdout.write(`${JSON.stringify({ ok: true, profileName, extensionId, extensionVersion, results }, null, 2)}\n`);
  } finally {
    await context.close();
    if (fixtureServer) await new Promise((resolve) => fixtureServer.close(resolve));
  }
}

main().catch((error) => {
  appendJsonLine(path.join(REPORT_DIR, "browser_results.jsonl"), {
    timestamp: new Date().toISOString(), runner: "PLAYWRIGHT", harnessError: String(error.stack || error)
  });
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
