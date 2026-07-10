"use strict";

const fs = require("fs");
const path = require("path");
const ArgusEngine = require("../engine/argus_engine.js");

const root = path.resolve(__dirname, "..");
const policy = JSON.parse(fs.readFileSync(path.join(root, "engine", "detection_policy.json"), "utf8"));
const categories = JSON.parse(fs.readFileSync(path.join(root, "risky_categories.json"), "utf8"));
const corpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "exfiltration_eval_cases.json"), "utf8"));

let failures = 0;
const groupStats = new Map();

for (const testCase of corpus.cases) {
  const result = ArgusEngine.evaluate(testCase.signals, categories, policy);
  const errors = [];
  const expected = testCase.expect || {};

  if (expected.level && result.level !== expected.level) errors.push(`level ${result.level}`);
  if (expected.category && result.category !== expected.category) errors.push(`category ${result.category}`);
  if (Number.isFinite(expected.min) && result.score < expected.min) errors.push(`score ${result.score} < ${expected.min}`);
  if (Number.isFinite(expected.max) && result.score > expected.max) errors.push(`score ${result.score} > ${expected.max}`);

  const stats = groupStats.get(testCase.group) || { passed: 0, total: 0 };
  stats.total += 1;

  if (errors.length > 0) {
    failures += 1;
    console.error(`FAIL ${testCase.id}: ${errors.join(", ")} (actual ${result.score} ${result.level} ${result.category})`);
  } else {
    stats.passed += 1;
    console.log(`PASS ${testCase.id}: ${result.score} ${result.level} ${result.category}`);
  }
  groupStats.set(testCase.group, stats);
}

console.log("\nGroup results:");
for (const [group, stats] of groupStats.entries()) {
  console.log(`- ${group}: ${stats.passed}/${stats.total}`);
}
console.log(`\n${corpus.cases.length - failures}/${corpus.cases.length} calibration cases passed (policy ${policy.version}).`);

if (failures > 0) {
  process.exitCode = 1;
}
