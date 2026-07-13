"use strict";

const fs = require("fs");
const path = require("path");
const ArgusEngine = require("../engine/argus_engine.js");

const root = path.resolve(__dirname, "..");
const policy = JSON.parse(fs.readFileSync(path.join(root, "engine", "detection_policy.json"), "utf8"));
const categories = JSON.parse(fs.readFileSync(path.join(root, "risky_categories.json"), "utf8"));
const corpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "randomized_web_eval_cases.json"), "utf8"));

let failures = 0;
let safeFalsePositives = 0;
let fakeFalseNegatives = 0;
const families = new Map();

for (const testCase of corpus.cases) {
  const result = ArgusEngine.evaluate(testCase.signals, categories, policy);
  const expected = testCase.expect || {};
  const errors = [];
  if (expected.level && result.level !== expected.level) errors.push(`level ${result.level}`);
  if (expected.category && result.category !== expected.category) errors.push(`category ${result.category}`);
  if (Number.isFinite(expected.min) && result.score < expected.min) errors.push(`score ${result.score} < ${expected.min}`);
  if (Number.isFinite(expected.max) && result.score > expected.max) errors.push(`score ${result.score} > ${expected.max}`);

  const stats = families.get(testCase.family) || { passed: 0, total: 0, minimum: 100, maximum: 0 };
  stats.total += 1;
  stats.minimum = Math.min(stats.minimum, result.score);
  stats.maximum = Math.max(stats.maximum, result.score);
  if (errors.length === 0) stats.passed += 1;
  families.set(testCase.family, stats);

  if (errors.length > 0) {
    failures += 1;
    if (testCase.label === "SAFE" && result.score >= 35) safeFalsePositives += 1;
    if (testCase.label === "FAKE" && result.score < 35) fakeFalseNegatives += 1;
    console.error(`FAIL ${testCase.id}: ${errors.join(", ")} (actual ${result.score} ${result.level} ${result.category})`);
  }
}

for (const [family, stats] of families.entries()) {
  console.log(`${family}: ${stats.passed}/${stats.total}, score ${stats.minimum}-${stats.maximum}`);
}
console.log(`Randomized result: ${corpus.cases.length - failures}/${corpus.cases.length}; SAFE false positives ${safeFalsePositives}/500; fake false negatives ${fakeFalseNegatives}/500.`);
if (failures > 0) process.exitCode = 1;
