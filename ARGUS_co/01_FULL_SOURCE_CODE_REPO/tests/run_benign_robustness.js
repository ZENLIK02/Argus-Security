"use strict";

const fs = require("fs");
const path = require("path");
const ArgusEngine = require("../engine/argus_engine.js");

const root = path.resolve(__dirname, "..");
const policy = JSON.parse(fs.readFileSync(path.join(root, "engine", "detection_policy.json"), "utf8"));
const categories = JSON.parse(fs.readFileSync(path.join(root, "risky_categories.json"), "utf8"));
const corpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "benign_robustness_cases.json"), "utf8"));

let failures = 0;
const groupStats = new Map();
for (const testCase of corpus.cases) {
  const result = ArgusEngine.evaluate(testCase.signals, categories, policy);
  const passed = result.level === "SAFE" && result.score <= testCase.expect.max;
  const stats = groupStats.get(testCase.group) || { passed: 0, total: 0, maximumScore: 0 };
  stats.total += 1;
  stats.maximumScore = Math.max(stats.maximumScore, result.score);
  if (passed) stats.passed += 1;
  else {
    failures += 1;
    console.error(`FAIL ${testCase.id}: ${result.score} ${result.level} ${result.category}`);
  }
  groupStats.set(testCase.group, stats);
}

for (const [group, stats] of groupStats.entries()) {
  console.log(`${group}: ${stats.passed}/${stats.total}, maximum score ${stats.maximumScore}`);
}
console.log(`${corpus.cases.length - failures}/${corpus.cases.length} benign robustness cases passed.`);
if (failures > 0) process.exitCode = 1;
