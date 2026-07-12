"use strict";
const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "..");
const content = fs.readFileSync(path.join(root, "content.js"), "utf8");
const worker = fs.readFileSync(path.join(root, "service_worker.js"), "utf8");
const popup = fs.readFileSync(path.join(root, "popup.js"), "utf8");
const policy = fs.readFileSync(path.join(root, "engine", "evidence_decision_policy.js"), "utf8");

assert(!content.includes("argus-warning-overlay"), "content still contains the top-right warning popup");
assert(!content.includes("renderPolicyOverlay"), "content still contains an overlay renderer");
assert(worker.includes("ArgusEvidencePolicy.decide"), "service worker does not invoke centralized policy");
assert(worker.includes("finalRisk.overlayAllowed = false"), "service worker does not globally disable visible overlays");
assert(!worker.includes("function shouldShowWarning"), "legacy score-based warning function still exists");
assert(!popup.includes("argus-warning-overlay"), "popup must not create a page overlay");
assert(policy.includes("modelOnly") && policy.includes("direct.length > 0"), "policy lacks explicit model-only/direct evidence enforcement");
assert(!/modelOnly[^\n]{0,120}overlayAllowed\s*=\s*true/.test(policy), "model-only code can allow an overlay");
console.log("PASS warning-path audit: top-right warning UI is absent and visible overlays are disabled.");

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
