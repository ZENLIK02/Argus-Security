"use strict";

const fs = require("fs");
const path = require("path");
const Identity = require("../engine/brand_identity.js");
const Policy = require("../engine/evidence_decision_policy.js");

const root = path.resolve(__dirname, "..");
const registry = JSON.parse(fs.readFileSync(path.join(root, "engine", "brand_registry.json"), "utf8"));
const corpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "impersonation_context_cases.json"), "utf8"));
let passed = 0;

for (const sample of corpus.cases) {
  const identity = Identity.analyze({ domain: sample.domain, identityTextSurface: sample.surface }, registry);
  const evidence = [];
  if (identity.claimedBrandIds.length) evidence.push(finding("CLAIMED_BRAND_IDENTITY"));
  if (identity.domainMismatch) evidence.push(finding("DOMAIN_IDENTITY_MISMATCH"));
  if (identity.primaryContext !== "UNKNOWN") evidence.push(finding("HIGH_VALUE_CONTEXT", identity.primaryContext));
  if (sample.sensitive) evidence.push(finding("SENSITIVE_ACTION_SURFACE", "SENSITIVE_ACTION"));
  const result = Policy.decide({
    legacyRisk: { score: 45, evidence, modelAnalysis: { score: 45 } },
    context: { scanPhase: "FINAL", identitySignals: identity, sensitivityMode: "BALANCED", sensitiveInteractionObserved: Boolean(sample.sensitive), reputation: { verdict: "UNKNOWN" } }
  });
  assert(identity.primaryContext === sample.expectContext, `${sample.id}: expected context ${sample.expectContext}, got ${identity.primaryContext}`);
  assert(result.status === sample.expectStatus, `${sample.id}: expected ${sample.expectStatus}, got ${result.status}`);
  if (sample.expectStatus === "RISKY_CONTEXT") {
    assert(result.warningAllowed && !result.overlayAllowed, `${sample.id}: early caution permissions are wrong`);
    assert(result.warningStage === "INTERACTION", `${sample.id}: sensitive caution did not reach interaction stage`);
  }
}

console.log(`${passed}/${passed} nine-context impersonation corpus assertions passed.`);

function finding(id, category = "BRAND_IMPERSONATION") { return { id, category, tool: "CORPUS", confidence: 0.9 }; }
function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } passed += 1; }
