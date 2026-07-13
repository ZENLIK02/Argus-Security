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
console.log("PASS report privacy audit: schema 2 contains no raw sensitive fields and requires label review.");

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
