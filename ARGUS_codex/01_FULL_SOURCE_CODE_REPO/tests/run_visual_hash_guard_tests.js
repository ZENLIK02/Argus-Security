"use strict";

const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
const offscreen = fs.readFileSync(path.join(root, "offscreen.js"), "utf8");
const worker = fs.readFileSync(path.join(root, "service_worker.js"), "utf8");
let passed = 0;
assert(manifest.permissions.includes("offscreen"), "offscreen permission is missing");
assert(offscreen.includes("MAX_IMAGE_BYTES = 512 * 1024"), "visual input has no strict size cap");
assert(offscreen.includes('parsed.protocol !== "https:"'), "visual hashing accepts non-HTTPS resources");
assert(offscreen.includes('credentials: "omit"'), "visual fetch may send site credentials");
assert(!/chrome\.storage|fetch\([^)]*backend|XMLHttpRequest/.test(offscreen), "offscreen visual worker persists or uploads image data");
assert(worker.includes("visualHashCache") && worker.includes("24 * 60 * 60 * 1000"), "visual hashes are not bounded by an ephemeral cache");
console.log(`${passed}/${passed} local visual-hash guard checks passed.`);

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } passed += 1; }
