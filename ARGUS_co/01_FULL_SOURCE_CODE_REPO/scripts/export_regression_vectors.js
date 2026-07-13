"use strict";
const fs = require("fs");
const path = require("path");
const Features = require("../engine/feature_extractor.js");
const root = path.resolve(__dirname, "..");
const files = ["exfiltration_eval_cases.json", "benign_robustness_cases.json", "randomized_web_eval_cases.json"];
const rows = files.flatMap((file) => JSON.parse(fs.readFileSync(path.join(root, "datasets", file), "utf8")).cases).map((item) => ({
  x: Features.vectorize(item.signals),
  y: Math.max(0, Math.min(1, Number(item.expect.targetScore) / 100)),
  level: item.expect.level
}));
fs.writeFileSync(path.join(root, "datasets", "regression_replay_vectors.json"), JSON.stringify(rows));
console.log(`Exported ${rows.length} regression replay vectors.`);
