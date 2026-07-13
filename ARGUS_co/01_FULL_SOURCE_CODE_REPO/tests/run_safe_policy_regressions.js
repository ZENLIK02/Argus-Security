"use strict";
const Policy = require("../engine/evidence_decision_policy.js");

const scenarios = [
  ["university login", ["PASSWORD_UNKNOWN_DOMAIN", "LOGIN_LANGUAGE"], 92],
  ["government portal", ["MISSING_BROWSER_PROTECTIONS"], 88],
  ["bank authentication", ["PASSWORD_UNKNOWN_DOMAIN", "OTP_UNKNOWN_DOMAIN"], 90],
  ["ecommerce checkout", ["LOGIN_LANGUAGE"], 78],
  ["Google Microsoft SSO", ["PASSWORD_UNKNOWN_DOMAIN"], 95],
  ["news ads analytics", ["AGGRESSIVE_AD_LAYOUT"], 74],
  ["developer documentation scripts", ["THIRD_PARTY_SCRIPT_NO_INTEGRITY"], 87],
  ["job application file upload", ["FILE_METADATA_ACCESS"], 82],
  ["social media", ["LOGIN_LANGUAGE"], 80],
  ["many safe iframes", ["MISSING_BROWSER_PROTECTIONS"], 86],
  ["many third-party assets", ["EXTERNAL_SCRIPT_CREDENTIAL_PAGE"], 75],
  ["generic POST", ["HTTP_FORM"], 60],
  ["analytics before interaction", [], 55],
  ["analytics after non-sensitive interaction", [], 65]
];

for (const [name, ids, modelScore] of scenarios) {
  const evidence = ids.map((id) => ({ id, tool: "SAFE_REGRESSION", category: id.includes("AD") ? "MALVERTISING" : "CONTEXT", message: id }));
  const result = Policy.decide({ legacyRisk: { score: modelScore, evidence, modelAnalysis: { score: modelScore } }, context: { scanPhase: "FINAL", destinationRoles: ["KNOWN_ANALYTICS", "CDN", "KNOWN_IDENTITY_PROVIDER"] } });
  assert(result.status !== "HIGH_RISK", `${name} became HIGH_RISK`);
  assert(result.status !== "SUSPICIOUS", `${name} became SUSPICIOUS from weak/model-only evidence`);
  assert(!result.overlayAllowed, `${name} allowed an overlay`);
}
console.log(`${scenarios.length}/14 safe policy regressions passed.`);

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
