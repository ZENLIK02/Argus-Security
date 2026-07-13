"use strict";
const fs = require("fs");
const path = require("path");
global.ArgusFeatureExtractor = require("../engine/feature_extractor.js");
global.ArgusTrainedModel = require("../engine/trained_model.json");
const Engine = require("../engine/argus_engine.js");
const Policy = require("../engine/evidence_decision_policy.js");
const root = path.resolve(__dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(root, "risky_categories.json"), "utf8"));
const enginePolicy = JSON.parse(fs.readFileSync(path.join(root, "engine", "detection_policy.json"), "utf8"));
const corpora = ["exfiltration_eval_cases.json", "benign_robustness_cases.json", "randomized_web_eval_cases.json"];
const cases = corpora.flatMap((file) => JSON.parse(fs.readFileSync(path.join(root, "datasets", file), "utf8")).cases);
let safe = 0, safeWarnings = 0, modelOnlyWarnings = 0, directHighRisk = 0;

for (const testCase of cases) {
  const legacy = Engine.evaluate(testCase.signals, config, enginePolicy);
  const result = Policy.decide({ legacyRisk: legacy, context: { scanPhase: "FINAL", navigationId: `test-${testCase.id}`, frameId: 0 } });
  if (testCase.expect.level === "SAFE") {
    safe += 1;
    if (result.warningAllowed || result.overlayAllowed) safeWarnings += 1;
  }
  if (result.modelOnly && (result.status === "SUSPICIOUS" || result.status === "HIGH_RISK" || result.warningAllowed || result.overlayAllowed)) modelOnlyWarnings += 1;
  if (result.directEvidence.length > 0) {
    assert(result.status === "HIGH_RISK", `${testCase.id}: direct evidence did not produce HIGH_RISK`);
    assert(result.overlayAllowed, `${testCase.id}: direct evidence did not allow overlay`);
    directHighRisk += 1;
  }
  if (result.status === "SUSPICIOUS") assert(result.evidenceGroups.length >= 2, `${testCase.id}: SUSPICIOUS lacks two evidence groups`);
}
assert(safeWarnings === 0, `safe cases produced ${safeWarnings} visible warnings`);
assert(modelOnlyWarnings === 0, `model-only paths produced ${modelOnlyWarnings} warnings`);
assert(directHighRisk > 0, "corpus contains no direct HIGH_RISK validation cases");
console.log(`PASS policy integration: ${safe} SAFE cases, 0 visible warnings; ${directHighRisk} direct-evidence HIGH_RISK cases.`);

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
