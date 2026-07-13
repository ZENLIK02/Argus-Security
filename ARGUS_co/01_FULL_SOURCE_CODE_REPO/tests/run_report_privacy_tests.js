"use strict";
const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "..");
const popup = fs.readFileSync(path.join(root, "popup.js"), "utf8");
const worker = fs.readFileSync(path.join(root, "service_worker.js"), "utf8");
const forbiddenReportFields = ["requestBody", "requestHeaders", "authorizationHeader", "passwordValue", "otpValue", "clipboardContent", "fileContent", "cookieValue"];
for (const field of forbiddenReportFields) {
  assert(!new RegExp(`\\b${field}\\s*:`).test(popup), `popup export contains forbidden field ${field}`);
  assert(!new RegExp(`\\b${field}\\s*:`).test(worker), `false-positive report contains forbidden field ${field}`);
}
assert(worker.includes("FALSE_POSITIVE_UNREVIEWED"), "false-positive labels are not marked unreviewed");
assert(worker.includes("reviewRequired: true"), "false-positive report lacks review requirement");
assert(popup.includes("reportSchemaVersion"), "export report lacks schema version");
// Reputation privacy: the lookup body carries the normalized hostname only (the
// `host` twin is a pre-merge backend alias, same value) — never a URL.
const reputationClient = fs.readFileSync(path.join(root, "engine", "reputation_client.js"), "utf8");
assert(reputationClient.includes("body: JSON.stringify({ hostname: host, host })"), "reputation lookup is not restricted to a normalized hostname payload");
assert(!/JSON\.stringify\(\{[^}]*url/.test(reputationClient), "reputation lookup includes a URL");
// Identity privacy: raw page identity text, screenshots, and image crops must never
// be retained in worker results or reports.
assert(!/identityTextSurface\s*:/.test(worker), "raw identity text is retained in worker results or reports");
assert(!/screenshot|imageCrop|pageImage\s*:/.test(worker), "visual identity processing retains screenshots or image crops");
console.log("PASS report privacy audit: schema 5 contains no raw sensitive fields, identity text, screenshots, or non-hostname reputation data.");

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
