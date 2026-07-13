"use strict";

// End-to-end reputation test: extension client -> REAL FastAPI backend -> reputation
// verdict -> evidence policy -> stored-result freshness. Spawns its own uvicorn on a
// private port with a temporary blocklist, drives the actual ArgusReputationClient
// (the same code the service worker runs), then tears everything down.
//
// Requires python + fastapi + uvicorn (backend/requirements.txt). If the backend
// cannot start, the test fails loudly rather than silently passing.

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

// Load engine modules the way the service worker does (globals + require).
global.ArgusReputation = require("../engine/reputation.js");
const Client = require("../engine/reputation_client.js");
const Policy = require("../engine/evidence_decision_policy.js");
const Freshness = require("../engine/scan_freshness.js");

const ROOT = path.resolve(__dirname, "..");
const BACKEND_DIR = path.join(ROOT, "backend");
const TEMP_BLOCKLIST = path.join(BACKEND_DIR, "data", "blocklists", "_e2e_temp.txt");
const PORT = 8791;
const BASE = `http://127.0.0.1:${PORT}`;
const ENDPOINT = `${BASE}/v1/reputation/check`;

let passed = 0;
function assert(condition, message) {
  if (!condition) throw new Error(`ASSERT FAILED: ${message}`);
  passed += 1;
}

function makeStorage() {
  const map = new Map();
  return {
    map,
    storageGet: async (keys) => {
      const out = {};
      for (const k of (Array.isArray(keys) ? keys : [keys])) if (map.has(k)) out[k] = map.get(k);
      return out;
    },
    storageSet: async (obj) => { for (const k of Object.keys(obj)) map.set(k, obj[k]); }
  };
}

function makeDeps(storage, fetchImpl) {
  const rescans = [];
  return {
    deps: {
      storageGet: storage.storageGet,
      storageSet: storage.storageSet,
      fetchImpl,
      getNavigationId: () => "nav-e2e",
      scheduleRescan: (tabId, scanPhase) => rescans.push({ tabId, scanPhase }),
      inFlight: new Set(),
      now: () => Date.now(),
      log: () => {}
    },
    rescans
  };
}

async function waitForHealth(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return await r.json();
    } catch (error) { /* not up yet */ }
    await new Promise((res) => setTimeout(res, 300));
  }
  throw new Error(`backend did not become healthy on ${BASE} within ${timeoutMs}ms`);
}

async function main() {
  // Temp blocklist listing example.net (and NOT example.org, used as the clean control).
  fs.mkdirSync(path.dirname(TEMP_BLOCKLIST), { recursive: true });
  fs.writeFileSync(TEMP_BLOCKLIST, "# e2e temp\nexample.net\n", "utf8");

  const server = spawn("python", ["-m", "uvicorn", "main:app", "--port", String(PORT), "--log-level", "warning"], {
    cwd: BACKEND_DIR, stdio: ["ignore", "ignore", "ignore"]
  });
  let serverError = null;
  server.on("error", (e) => { serverError = e; });

  let cleaned = false;
  const cleanup = () => new Promise((resolve) => {
    try { fs.unlinkSync(TEMP_BLOCKLIST); } catch (e) { /* ignore */ }
    if (cleaned || server.killed || server.exitCode !== null) { cleaned = true; return resolve(); }
    cleaned = true;
    server.once("close", () => resolve());
    setTimeout(resolve, 3000);
    try { server.kill("SIGKILL"); } catch (e) { resolve(); }
  });

  try {
    const health = await waitForHealth(30000);
    if (serverError) throw serverError;
    assert(health.ok === true, "backend /health ok");
    assert(health.blocklistDomains >= 1, "backend loaded the temp blocklist");

    const settings = { reputationEnabled: true, reputationEndpoint: ENDPOINT };

    // --- A) malicious host: refresh performs the real fetch, caches, schedules rescan ---
    const storage = makeStorage();
    const { deps, rescans } = makeDeps(storage, fetch);
    const refreshResult = await Client.refresh("example.net", 7, settings, deps);
    assert(refreshResult.cached === true, "malicious verdict was cached");
    assert(refreshResult.rescanScheduled === true, "malicious verdict scheduled a rescan");
    assert(rescans.length === 1 && rescans[0].scanPhase === "INTERACTION_FINAL", "rescan uses INTERACTION_FINAL (highest phase)");
    const cachedEntry = storage.map.get(ArgusReputation.cacheKey("example.net"));
    assert(cachedEntry && cachedEntry.listed === true && cachedEntry.available === true, "cache holds a listed verdict");
    const diag = storage.map.get("lastReputationDiag");
    assert(diag && diag.httpStatus === 200 && diag.verdict === "MALICIOUS" && !diag.error, "diagnostics recorded HTTP 200 MALICIOUS");

    // --- B) resolve reads cache -> policy -> HIGH_RISK 95 with REPUTATION_BLOCKLISTED ---
    const resolved = await Client.resolve({ domain: "example.net", isTrustedDomain: false }, settings, 7, deps);
    assert(resolved.diag.cache === "hit" && resolved.diag.applied === true, "resolve hit cache and applied verdict");
    assert(resolved.context && resolved.context.listed === true, "resolve returned a listed policy context");
    const decision = Policy.decide({
      legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } },
      context: { scanPhase: "FINAL", navigationId: "nav-e2e", reputation: resolved.context }
    });
    assert(decision.status === "HIGH_RISK", `policy produced ${decision.status}`);
    assert(decision.score >= 95, `policy score ${decision.score} < 95`);
    assert(decision.reputationDirectEvidenceIds.includes("REPUTATION_BLOCKLISTED"), "REPUTATION_BLOCKLISTED evidence present");
    assert(decision.warningAllowed && decision.overlayAllowed, "warning + overlay allowed");

    // --- C) stored-result freshness: HIGH_RISK (INTERACTION_FINAL) must not be
    //         overwritten by a stale SAFE (lower phase), and it replaces an old FINAL ---
    const safePrelim = { navigationId: "nav-e2e", scanPhase: "PRELIMINARY", timestamp: "2026-07-12T10:00:00.000Z" };
    const safeFinal = { navigationId: "nav-e2e", scanPhase: "FINAL", timestamp: "2026-07-12T10:00:03.000Z" };
    const repHigh = { navigationId: "nav-e2e", scanPhase: "INTERACTION_FINAL", timestamp: "2026-07-12T10:00:04.000Z" };
    assert(Freshness.shouldReplaceStoredScan(safeFinal, repHigh) === true, "reputation INTERACTION_FINAL replaces a SAFE FINAL");
    assert(Freshness.shouldReplaceStoredScan(repHigh, safePrelim) === false, "a stale SAFE PRELIMINARY cannot overwrite the reputation HIGH_RISK");

    // --- D) clean control host: not listed -> unknown -> SAFE, no rescan ---
    const cleanStorage = makeStorage();
    const cleanCtx = makeDeps(cleanStorage, fetch);
    const cleanRefresh = await Client.refresh("example.org", 8, settings, cleanCtx.deps);
    assert(cleanRefresh.verdict.listed === false, "clean host verdict is not listed");
    assert(cleanCtx.rescans.length === 0, "clean host does not schedule a rescan");
    const cleanResolved = await Client.resolve({ domain: "example.org", isTrustedDomain: false }, settings, 8, cleanCtx.deps);
    // A clean-but-available verdict yields a context with listed=false (harmless — it
    // produces no reputation evidence); it must never be listed.
    assert(!cleanResolved.context || cleanResolved.context.listed === false, "clean host must not yield a listed context");
    const cleanDecision = Policy.decide({ legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } }, context: { scanPhase: "FINAL", navigationId: "nav-e2e", reputation: cleanResolved.context } });
    assert(cleanDecision.status !== "HIGH_RISK", "clean host is not HIGH_RISK");

    // --- D2) reviewed seed host: graded RISKY_CONTEXT verdict -> early caution,
    //          NOT listed, NO rescan (rescans are reserved for MALICIOUS) ---
    const seedStorage = makeStorage();
    const seedCtx = makeDeps(seedStorage, fetch);
    const seedRefresh = await Client.refresh("sexy365bet.net", 10, settings, seedCtx.deps);
    assert(seedRefresh.verdict.verdict === "RISKY_CONTEXT", `seed host verdict ${seedRefresh.verdict.verdict}`);
    assert(seedRefresh.verdict.listed === false, "seed host is not listed");
    assert(seedCtx.rescans.length === 0, "RISKY_CONTEXT verdict does not schedule a rescan");
    const seedResolved = await Client.resolve({ domain: "sexy365bet.net", isTrustedDomain: false }, settings, 10, seedCtx.deps);
    assert(seedResolved.context && seedResolved.context.verdict === "RISKY_CONTEXT", "resolve returns the graded verdict");
    const seedDecision = Policy.decide({
      legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } },
      context: { scanPhase: "FINAL", navigationId: "nav-e2e", reputation: seedResolved.context }
    });
    assert(seedDecision.status === "RISKY_CONTEXT", `seed policy status ${seedDecision.status}`);
    assert(seedDecision.score === 48, `seed policy score ${seedDecision.score}`);
    assert(seedDecision.warningAllowed && !seedDecision.overlayAllowed, "seed caution warns without an overlay");
    assert(seedDecision.warningStage === "BADGE", "seed caution starts at the badge stage");

    // --- E) backend outage: fetch fails -> non-fatal, not cached, error surfaced ---
    const outageStorage = makeStorage();
    const outageCtx = makeDeps(outageStorage, fetch);
    const deadSettings = { reputationEnabled: true, reputationEndpoint: "http://127.0.0.1:8799/v1/reputation/check" };
    const outageRefresh = await Client.refresh("example.net", 9, deadSettings, outageCtx.deps);
    assert(outageRefresh.verdict.available === false, "backend outage yields unavailable verdict");
    assert(!outageStorage.map.has(ArgusReputation.cacheKey("example.net")), "outage verdict is NOT cached (will retry)");
    const outageResolved = await Client.resolve({ domain: "example.net", isTrustedDomain: false }, deadSettings, 9, outageCtx.deps);
    assert(outageResolved.context === undefined, "outage keeps scanning non-fatal (no reputation context)");

    console.log(`${passed}/${passed} reputation end-to-end cases passed (real backend on ${BASE}).`);
  } finally {
    await cleanup();
  }
}

// No forced process.exit: let the loop drain after the spawned backend is killed and
// its handles close (avoids a Windows libuv async-handle assertion during teardown).
main().catch((error) => {
  console.error(`FAIL ${error.message}`);
  process.exitCode = 1;
});
