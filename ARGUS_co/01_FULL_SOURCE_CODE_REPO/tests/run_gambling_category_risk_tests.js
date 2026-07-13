"use strict";

const fs = require("fs");
const path = require("path");
const Policy = require("../engine/evidence_decision_policy.js");
const Shared = require("../engine/shared_lists.js");

const root = path.resolve(__dirname, "..");
const incidents = JSON.parse(fs.readFileSync(path.join(root, "datasets", "field_incidents_gambling_2026-07-12.json"), "utf8"));
const seed = JSON.parse(fs.readFileSync(path.join(root, "backend", "reputation_seed.json"), "utf8"));
const seededHosts = new Set(seed.entries.map((entry) => entry.hostname));

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

for (const sample of incidents.cases) {
  assert(seededHosts.has(sample.hostname), `${sample.hostname} is missing from the reviewed reputation seed`);
  assert(Shared.GAMBLING_DOMAIN_PATTERNS.some((pattern) => sample.hostname.includes(pattern)), `${sample.hostname} lacks an offline gambling-domain pattern`);
  const result = Policy.decide({
    legacyRisk: {
      score: 35,
      evidence: [
        { id: "GAMBLING_CONTENT", tool: "CONTENT_ANALYZER", category: "GAMBLING" },
        { id: "SENSITIVE_ACTION_SURFACE", tool: "CREDENTIAL_ANALYZER", category: "SENSITIVE_ACTION" },
        { id: "REPUTATION_RISKY_CONTEXT", tool: "REPUTATION_ANALYZER", category: "GAMBLING_UNVERIFIED" }
      ],
      modelAnalysis: { score: 35, version: "field-regression" }
    },
    context: { scanPhase: "FINAL", reputation: { verdict: "RISKY_CONTEXT" }, navigationId: "field-test", frameId: 0 }
  });
  assert(result.status === "RISKY_CONTEXT", `${sample.hostname} did not produce RISKY_CONTEXT`);
  assert(result.warningAllowed && !result.overlayAllowed, `${sample.hostname} category warning permissions are wrong`);
  assert(result.reasons.some((reason) => /does not claim|not confirmed/i.test(reason)), `${sample.hostname} warning must avoid a data-theft claim`);
}

const offlineFallback = Policy.decide({
  legacyRisk: { score: 3, evidence: [{ id: "GAMBLING_CONTENT", tool: "CONTENT_ANALYZER", category: "GAMBLING" }], modelAnalysis: { score: 3 } },
  context: { scanPhase: "FINAL", reputation: { verdict: "UNAVAILABLE" } }
});
assert(offlineFallback.status === "RISKY_CONTEXT" && offlineFallback.warningAllowed, "reputation outage downgraded local gambling evidence");

console.log(`${passed}/${passed} gambling category-risk field regressions passed.`);
