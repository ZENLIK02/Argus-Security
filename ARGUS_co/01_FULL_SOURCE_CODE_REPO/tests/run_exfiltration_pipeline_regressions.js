"use strict";

const Policy = require("../engine/evidence_decision_policy.js");

function decide(legacyRisk, networkSignals = {}) {
  return Policy.decide({
    legacyRisk,
    context: {
      scanPhase: "FINAL",
      navigationId: "pipeline-regression",
      networkSignals
    }
  });
}

const fallbackRisk = { score: 100, level: "HIGH_RISK", evidence: [], modelAnalysis: { score: 100, version: "test" } };
const confirmed = decide(fallbackRisk, {
  crossDomainSensitiveWriteRequests: 1,
  temporalSignals: { crossDomainSensitiveWriteCount: 1 }
});
assert(confirmed.status === "HIGH_RISK", `confirmed exfiltration became ${confirmed.status}`);
assert(confirmed.score > 5, `confirmed exfiltration was capped at ${confirmed.score}`);
assert(confirmed.telemetryDirectEvidenceIds.includes("CROSS_DOMAIN_SENSITIVE_WRITE"), "telemetry direct evidence was not retained");
assert(confirmed.warningAllowed, "confirmed exfiltration did not permit a warning");

const modelOnly = decide(fallbackRisk);
assert(modelOnly.modelOnly, "model-only classification was lost");
assert(modelOnly.score <= 5, `model-only score escaped cap: ${modelOnly.score}`);
assert(!modelOnly.warningAllowed, "model-only result permitted a warning");

const safe = decide({ score: 80, level: "HIGH_RISK", evidence: [], modelAnalysis: { score: 80, version: "test" } }, {
  totalRequests: 120,
  thirdPartyRequests: 70,
  thirdPartyXHRRequests: 20,
  destinationRoleCounts: { KNOWN_ANALYTICS: 20, CDN: 30, STATIC_ASSET: 20 }
});
assert(safe.score <= 5, `benign telemetry received score ${safe.score}`);
assert(!safe.warningAllowed && !safe.overlayAllowed, "benign telemetry permitted a warning");

console.log("3/3 exfiltration pipeline regression cases passed.");

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL ${message}`);
    process.exit(1);
  }
}
