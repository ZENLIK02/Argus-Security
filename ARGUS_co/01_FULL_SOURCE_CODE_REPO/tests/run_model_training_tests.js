"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const corpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "exfiltration_eval_cases.json"), "utf8"));
const benignCorpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "benign_robustness_cases.json"), "utf8"));
const randomizedCorpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "randomized_web_eval_cases.json"), "utf8"));
const model = JSON.parse(fs.readFileSync(path.join(root, "engine", "trained_model.json"), "utf8"));
const Features = require("../engine/feature_extractor.js");

assert(corpus.cases.length === 200, `expected 200 corpus cases, got ${corpus.cases.length}`);
assert(benignCorpus.cases.length === 200, `expected 200 benign robustness cases, got ${benignCorpus.cases.length}`);
assert(randomizedCorpus.cases.length === 1000, `expected 1000 randomized cases, got ${randomizedCorpus.cases.length}`);
assert(new Set(corpus.cases.map((item) => item.id)).size === 200, "corpus case IDs must be unique");
assert(new Set(benignCorpus.cases.map((item) => item.id)).size === 200, "benign corpus case IDs must be unique");
assert(randomizedCorpus.cases.filter((item) => item.label === "SAFE").length === 500, "randomized corpus must contain 500 SAFE cases");
assert(randomizedCorpus.cases.filter((item) => item.label === "FAKE").length === 500, "randomized corpus must contain 500 fake cases");
assert(model.totalCaseCount === 1260000, `model must train on all 1,260,000 records, got ${model.totalCaseCount}`);
assert(model.optimizationSteps >= 10000, `model must complete at least 10,000 optimization steps, got ${model.optimizationSteps}`);
assert(model.featureCount === Features.FEATURE_NAMES.length, "feature count must match extractor");
assert(JSON.stringify(model.featureNames) === JSON.stringify(Features.FEATURE_NAMES), "model feature order must match extractor");
const cases = corpus.cases.concat(benignCorpus.cases, randomizedCorpus.cases);
const predictions = cases.map((testCase) => Features.predict(testCase.signals, model));
assert(predictions.every((prediction) => prediction && prediction.score >= 0 && prediction.score <= 100), "all model predictions must be bounded to 0-100");
let safe = 0, falsePositives = 0, risky = 0, falseNegatives = 0, highRisk = 0, highRiskHits = 0;
cases.forEach((testCase, index) => {
  const score = predictions[index].score;
  if (testCase.expect.level === "SAFE") { safe += 1; if (score >= 35) falsePositives += 1; }
  else { risky += 1; if (score < 35) falseNegatives += 1; }
  if (testCase.expect.level === "HIGH_RISK") { highRisk += 1; if (score >= 70) highRiskHits += 1; }
});
assert(falsePositives / safe <= 0.005, `raw calibrator SAFE false-positive rate above 0.5%: ${falsePositives}/${safe}`);
assert(1 - falseNegatives / risky >= 0.98, `raw calibrator risk recall below 98%: ${risky - falseNegatives}/${risky}`);
assert(highRiskHits / highRisk >= 0.95, `raw calibrator high-risk recall below 95%: ${highRiskHits}/${highRisk}`);
assert(model.metrics.fullTest.caseCount >= 120000, "full mega test holdout is missing");

console.log(`PASS full model: ${model.totalCaseCount} records, ${model.featureCount} features, ${model.optimizationSteps} Adam updates.`);
console.log(`PASS regression replay: SAFE FP ${falsePositives}/${safe}, risk recall ${risky - falseNegatives}/${risky}, high-risk recall ${highRiskHits}/${highRisk}.`);
console.log(`PASS full holdout: ${model.metrics.fullTest.caseCount} cases, SAFE FP ${(model.metrics.fullTest.safeFalsePositiveRate * 100).toFixed(2)}%.`);

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL ${message}`);
    process.exit(1);
  }
}
