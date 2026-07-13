"use strict";

// Coverage for the P1 reputation module: domain normalization, cache TTL, the
// query gate, and verdict parsing that feeds the evidence policy.
const R = require("../engine/reputation.js");

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

// normalizeDomain.
assert(R.normalizeDomain("  EVIL.Example.COM.  ") === "evil.example.com", "domain not normalized (case/trim/trailing dot)");
assert(R.cacheKey("Evil.com") === "rep:evil.com", "cache key not normalized");

// Freshness / TTL.
const now = 1_000_000_000_000;
assert(R.isFresh({ checkedAt: now - 1000 }, now, 10_000) === true, "recent entry treated as stale");
assert(R.isFresh({ checkedAt: now - 20_000 }, now, 10_000) === false, "expired entry treated as fresh");
assert(R.isFresh(null, now, 10_000) === false, "missing entry treated as fresh");

// Query gate: untrusted public hosts only.
assert(R.shouldQuery("evil.example.com", false) === true, "untrusted public host was not queryable");
assert(R.shouldQuery("evil.example.com", true) === false, "trusted host was queried");
assert(R.shouldQuery("localhost", false) === false, "localhost was queried");
assert(R.shouldQuery("127.0.0.1", false) === false, "loopback IP was queried");
assert(R.shouldQuery("10.0.0.5", false) === false, "raw IP host was queried");
assert(R.shouldQuery("", false) === false, "empty host was queried");
assert(R.shouldQuery("nodots", false) === false, "host without a dot was queried");

// Verdict parsing (canonical /v1/reputation/check response shape).
const listed = R.verdictFromResponse({ ok: true, host: "evil.com", listed: true, verdict: "malicious", source: "LOCAL_BLOCKLIST", matchedDomain: "evil.com" });
assert(listed.available && listed.listed && listed.source === "LOCAL_BLOCKLIST" && listed.matchedDomain === "evil.com", "listed verdict not parsed");
const clean = R.verdictFromResponse({ ok: true, host: "example.org", listed: false, verdict: "unknown", source: "NONE" });
assert(clean.available && clean.listed === false && clean.source === "NONE", "clean verdict not parsed");
// verdict:"malicious" alone (no `listed` field) must still count as listed.
const verdictOnly = R.verdictFromResponse({ ok: true, host: "bad.com", verdict: "malicious", matchedDomain: "bad.com" });
assert(verdictOnly.listed === true && verdictOnly.matchedDomain === "bad.com", "verdict:malicious not treated as listed");
assert(R.verdictFromResponse({ verdict: "unknown" }).listed === false, "verdict:unknown wrongly treated as listed");
const junk = R.verdictFromResponse(null);
assert(junk.available && junk.listed === false, "malformed response not treated as not-listed");
const down = R.unavailableVerdict();
assert(down.available === false && down.listed === false, "unavailable verdict incorrect");

// Policy context shape.
const ctx = R.toPolicyContext(listed);
assert(ctx.listed === true && ctx.source === "LOCAL_BLOCKLIST", "policy context shape incorrect");
assert(R.toPolicyContext(clean).listed === false, "clean policy context should not be listed");

// Integration chain (proves the live path end to end, minus the browser): a
// malicious backend response must flow verdict -> policy context -> decide ->
// HIGH_RISK 95 with REPUTATION_BLOCKLISTED, and must NOT be dropped anywhere.
const Policy = require("../engine/evidence_decision_policy.js");
const backendMalicious = { ok: true, host: "example.net", domain: "example.net", listed: true, verdict: "malicious", source: "LOCAL_BLOCKLIST", matchedDomain: "example.net" };
const maliciousDecision = Policy.decide({
  legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } },
  context: { scanPhase: "FINAL", navigationId: "nav", reputation: R.toPolicyContext(R.verdictFromResponse(backendMalicious)) }
});
assert(maliciousDecision.status === "HIGH_RISK", `malicious verdict did not reach HIGH_RISK (got ${maliciousDecision.status})`);
assert(maliciousDecision.score >= 95, `malicious verdict score below 95 (got ${maliciousDecision.score})`);
assert(maliciousDecision.reputationDirectEvidenceIds.includes("REPUTATION_BLOCKLISTED"), "REPUTATION_BLOCKLISTED evidence was dropped");
assert(maliciousDecision.directEvidence.some((e) => e.id === "REPUTATION_BLOCKLISTED"), "REPUTATION_BLOCKLISTED missing from directEvidence");
assert(maliciousDecision.warningAllowed && maliciousDecision.overlayAllowed, "malicious verdict did not allow a warning/overlay");

// A malicious verdict at a NON-final phase must stay pending (not warn early).
const preliminary = Policy.decide({
  legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } },
  context: { scanPhase: "PRELIMINARY", navigationId: "nav", reputation: R.toPolicyContext(R.verdictFromResponse(backendMalicious)) }
});
assert(preliminary.status !== "HIGH_RISK" && !preliminary.warningAllowed, "reputation warned before a final phase");

// A clean verdict must NOT create risk.
const cleanDecision = Policy.decide({
  legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } },
  context: { scanPhase: "FINAL", navigationId: "nav", reputation: R.toPolicyContext(R.verdictFromResponse({ ok: true, listed: false, verdict: "unknown", source: "NONE" })) }
});
assert(cleanDecision.status !== "HIGH_RISK", "clean verdict wrongly produced HIGH_RISK");
assert(!cleanDecision.reputationDirectEvidenceIds.includes("REPUTATION_BLOCKLISTED"), "clean verdict wrongly added reputation evidence");

// --- Graded verdict vocabulary (merge of the codex fork's schema) ---
const gradedSeed = R.verdictFromResponse({ ok: true, hostname: "seed.example", verdict: "RISKY_CONTEXT", confidence: "HIGH", sources: ["REVIEWED_SEED"], categories: ["GAMBLING_UNVERIFIED"] });
assert(gradedSeed.verdict === "RISKY_CONTEXT" && gradedSeed.listed === false, "RISKY_CONTEXT verdict must parse and stay unlisted");
assert(R.verdictFromResponse({ verdict: "RISKY_CATEGORY" }).verdict === "RISKY_CONTEXT", "legacy RISKY_CATEGORY must normalize to RISKY_CONTEXT");
assert(R.verdictFromResponse({ verdict: "MALICIOUS" }).listed === true, "MALICIOUS verdict string must imply listed");
assert(R.verdictFromResponse({ verdict: "nonsense" }).verdict === "UNKNOWN", "unrecognized verdicts must degrade to UNKNOWN");
assert(R.ttlForVerdict("MALICIOUS") === R.REPUTATION_TTL_MS, "MALICIOUS keeps the 6h TTL");
assert(R.ttlForVerdict("RISKY_CONTEXT") === 60 * 60 * 1000, "RISKY_CONTEXT uses a 1h TTL");
assert(R.ttlForVerdict("UNKNOWN") === 30 * 60 * 1000, "UNKNOWN uses a 30min TTL");
const staleRisky = { available: true, verdict: "RISKY_CONTEXT", checkedAt: Date.now() - 2 * 60 * 60 * 1000 };
assert(!R.isFresh(staleRisky, Date.now()), "a 2h-old RISKY_CONTEXT entry must be stale");
const freshMalicious = { available: true, verdict: "MALICIOUS", listed: true, checkedAt: Date.now() - 2 * 60 * 60 * 1000 };
assert(R.isFresh(freshMalicious, Date.now()), "a 2h-old MALICIOUS entry is still fresh (6h TTL)");
const riskyContextPolicy = Policy.decide({
  legacyRisk: { score: 0, evidence: [], modelAnalysis: { score: 0 } },
  context: { scanPhase: "FINAL", navigationId: "nav", reputation: R.toPolicyContext(gradedSeed) }
});
assert(riskyContextPolicy.status === "RISKY_CONTEXT", `graded seed verdict must produce RISKY_CONTEXT (got ${riskyContextPolicy.status})`);
assert(riskyContextPolicy.warningAllowed && !riskyContextPolicy.overlayAllowed, "graded caution warns without overlay");

// --- Settings migration guard (merge): the worker must keep an explicit pre-merge
// useReputation:false opt-out when introducing the canonical reputationEnabled key.
const fs = require("fs");
const path = require("path");
const workerSource = fs.readFileSync(path.join(__dirname, "..", "service_worker.js"), "utf8");
assert(workerSource.includes("raw.reputationEnabled !== undefined ? raw.reputationEnabled !== false : raw.useReputation !== false"), "service worker lost the useReputation -> reputationEnabled migration");
assert(!/settings\.useReputation/.test(workerSource), "service worker still reads the retired settings.useReputation key");

console.log(`${passed}/${passed} reputation module cases passed.`);
