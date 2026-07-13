"use strict";
const Policy = require("../engine/evidence_decision_policy.js");

const finding = (id, category = "DATA_EXFILTRATION") => ({ id, category, tool: "TEST", message: id, confidence: 0.9 });
const decide = (evidence = [], modelScore = 0, extra = {}) => Policy.decide({
  legacyRisk: { score: modelScore, level: modelScore >= 70 ? "HIGH_RISK" : modelScore >= 35 ? "SUSPICIOUS" : "SAFE", evidence, modelAnalysis: { score: modelScore, version: "test" } },
  context: { scanPhase: "FINAL", navigationId: "nav-test", frameId: 0, timestamp: "2026-01-01T00:00:00Z", ...extra }
});

const cases = [
  ["model 100 only", decide([], 100), "SAFE", false],
  ["known modern login context", decide([finding("PASSWORD_UNKNOWN_DOMAIN"), finding("LOGIN_LANGUAGE")], 90, { destinationRoles: ["KNOWN_IDENTITY_PROVIDER", "KNOWN_ANALYTICS"] }), "SAFE", false],
  ["password through HTTP", decide([finding("SENSITIVE_HTTP_FORM", "INSECURE_FORM_SUBMISSION")], 88), "HIGH_RISK", true],
  ["sensitive unknown POST", decide([finding("CROSS_DOMAIN_SENSITIVE_WRITE")], 95), "HIGH_RISK", true],
  ["telemetry-only sensitive unknown POST", decide([], 95, { networkSignals: { crossDomainSensitiveWriteRequests: 1 } }), "HIGH_RISK", true],
  ["beacon intent plus dynamic endpoint", decide([finding("EXFILTRATION_SEQUENCE"), finding("DYNAMIC_ENDPOINT")], 65), "SUSPICIOUS", false],
  ["sensitive context plus one SPA group", decide([finding("OTP_UNKNOWN_DOMAIN"), finding("DYNAMIC_ENDPOINT")], 70), "MONITORING", false],
  ["images and ads only", decide([finding("AGGRESSIVE_AD_LAYOUT", "MALVERTISING")], 45), "SAFE", false],
  ["category only", decide([finding("GAMBLING_CONTENT", "GAMBLING")], 80), "SAFE", false],
  ["apk download link only", decide([finding("APK_HREF", "MALICIOUS_APK")], 40), "MONITORING", false],
  ["reputation blocklisted (no other evidence)", decide([], 10, { reputation: { listed: true, source: "LOCAL_BLOCKLIST" } }), "HIGH_RISK", true],
  ["reputation clean", decide([], 10, { reputation: { listed: false } }), "SAFE", false],
  ["homoglyph brand domain", decide([finding("HOMOGLYPH_BRAND_DOMAIN", "BRAND_IMPERSONATION")], 20), "HIGH_RISK", true],
  ["typosquat brand lookalike only", decide([finding("DOMAIN_BRAND_LOOKALIKE", "BRAND_IMPERSONATION")], 20), "MONITORING", false],
  ["typosquat plus credentials escalates", decide([finding("DOMAIN_BRAND_LOOKALIKE", "BRAND_IMPERSONATION"), finding("PASSWORD_UNKNOWN_DOMAIN", "PHISHING_LOGIN")], 30), "SUSPICIOUS", false],
  ["fake bank full flow, high model, no observed behavior", decide([finding("FAKE_BANK_FULL_FLOW", "FAKE_BANKING"), finding("PASSWORD_UNKNOWN_DOMAIN")], 90), "MONITORING", false],
  ["brand lookalike credential flow escalates with observed group", decide([finding("SUSPICIOUS_DOMAIN_CREDENTIAL_FLOW", "PHISHING_LOGIN"), finding("CROSS_DOMAIN_FORM")], 80), "SUSPICIOUS", false],
  ["known SSO", decide([finding("PASSWORD_UNKNOWN_DOMAIN")], 70, { destinationRoles: ["KNOWN_IDENTITY_PROVIDER", "SSO_REDIRECT"] }), "SAFE", false],
  ["static dynamic plus hidden frame", decide([finding("DYNAMIC_ENDPOINT"), finding("HIDDEN_FRAME_WITH_CREDENTIALS")], 60), "MONITORING", false],
  ["static dynamic plus consent logic", decide([finding("DYNAMIC_ENDPOINT"), finding("POPUP_MESSAGE_RELAY")], 60), "MONITORING", false],
  ["trusted static application code", decide([finding("DYNAMIC_ENDPOINT"), finding("HIDDEN_FRAME_WITH_CREDENTIALS")], 60, { isTrustedDomain: true }), "SAFE", false]
];

for (const [name, result, status, overlay] of cases) {
  assert(result.status === status, `${name}: expected ${status}, got ${result.status}`);
  assert(result.overlayAllowed === overlay, `${name}: expected overlay=${overlay}, got ${result.overlayAllowed}`);
}
assert(cases[0][1].modelOnly, "model-only result must be explicit");
assert(!cases[0][1].warningAllowed, "model-only result must never allow warning");
assert(cases[0][1].score <= 5, "model-only result must not display risk above 5");
assert(cases.find((entry) => entry[0] === "telemetry-only sensitive unknown POST")[1].score > 5, "service-worker confirmed exfiltration must exceed the model-only cap");
assert(decide([], 34).score <= 5, "no-evidence legacy/model score must not leak above 5");
assert(decide([finding("OTP_UNKNOWN_DOMAIN")], 34).score <= 5, "weak sensitive-input context must not leak a model-only score above 5");
assert(cases.find((entry) => entry[0] === "known SSO")[1].score <= 5, "known SSO with only weak input context must remain at or below 5");
assert(cases.find((entry) => entry[0] === "images and ads only")[1].score <= 5, "ads-only score must be capped at 5");
assert(cases.find((entry) => entry[0] === "category only")[1].score <= 10, "category-only score must be capped at 10");
const reputationCase = cases.find((entry) => entry[0] === "reputation blocklisted (no other evidence)")[1];
assert(reputationCase.reputationDirectEvidenceIds.includes("REPUTATION_BLOCKLISTED"), "reputation blocklist hit did not create direct evidence");
assert(reputationCase.score >= 90, "reputation blocklist hit must be top-severity");
assert(reputationCase.warningAllowed, "reputation blocklist hit must allow a warning");
assert(cases.find((entry) => entry[0] === "beacon intent plus dynamic endpoint")[1].evidenceGroups.length >= 2, "SUSPICIOUS requires two independent groups");
assert(cases.find((entry) => entry[0] === "sensitive context plus one SPA group")[1].score <= 10, "one uncorrelated behavioral group must not score above 10");
assert(cases.find((entry) => entry[0] === "static dynamic plus hidden frame")[1].score <= 10 && cases.find((entry) => entry[0] === "static dynamic plus consent logic")[1].score <= 10, "static intent groups must not score above 10 without observed behavior");
assert(cases.filter((entry) => entry[2] === "SUSPICIOUS").every((entry) => {
  const groups = entry[1].evidenceGroups;
  const twoBehavioral = groups.filter((group) => group !== "SENSITIVE_INPUT").length >= 2;
  const impersonation = groups.includes("BRAND_IMPERSONATION") && (groups.includes("SENSITIVE_INPUT") || groups.includes("CREDENTIAL_PHISHING"));
  return twoBehavioral || impersonation;
}), "SUSPICIOUS requires two behavioral groups or a brand-impersonation + credential correlation");
const p3Case = cases.find((entry) => entry[0] === "typosquat plus credentials escalates")[1];
assert(p3Case.warningAllowed, "typosquat + credentials must allow a warning");
assert(p3Case.evidenceLevel === "BRAND_IMPERSONATION_PHISHING", "typosquat + credentials evidence level not tagged");
console.log(`${cases.length}/${cases.length} evidence-first policy cases passed.`);

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
