"use strict";

// Regression coverage for false-positive feedback egress pinning (F16): reports
// may only ever be delivered to a local loopback collector, never off-device.
const FE = require("../engine/feedback_endpoint.js");

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

const DEFAULT = "http://localhost:8000/feedback/false-positive";

// Loopback hosts are recognized.
assert(FE.isLoopbackHost("localhost"), "localhost not recognized as loopback");
assert(FE.isLoopbackHost("127.0.0.1"), "127.0.0.1 not recognized as loopback");
assert(FE.isLoopbackHost("127.5.6.7"), "127.0.0.0/8 loopback range not recognized");
assert(FE.isLoopbackHost("::1"), "IPv6 loopback not recognized");
assert(FE.isLoopbackHost("[::1]"), "bracketed IPv6 loopback not recognized");
assert(!FE.isLoopbackHost("evil.example.com"), "external host wrongly treated as loopback");
assert(!FE.isLoopbackHost("10.0.0.5"), "private-LAN host wrongly treated as loopback");
assert(!FE.isLoopbackHost("localhost.evil.com"), "look-alike host wrongly treated as loopback");

// Loopback endpoints are kept.
assert(FE.normalizeFeedbackEndpoint("http://localhost:8000/x", DEFAULT) === "http://localhost:8000/x", "loopback endpoint was not kept");
assert(FE.normalizeFeedbackEndpoint("http://127.0.0.1:9000/feedback", DEFAULT) === "http://127.0.0.1:9000/feedback", "127.0.0.1 endpoint was not kept");

// Any non-loopback or non-http(s) endpoint is forced back to the local default.
assert(FE.normalizeFeedbackEndpoint("https://evil.example.com/collect", DEFAULT) === DEFAULT, "external endpoint was NOT reverted (off-device exfiltration risk)");
assert(FE.normalizeFeedbackEndpoint("http://10.0.0.5/x", DEFAULT) === DEFAULT, "private-LAN endpoint was not reverted");
assert(FE.normalizeFeedbackEndpoint("ftp://localhost/x", DEFAULT) === DEFAULT, "non-http(s) scheme was not reverted");
assert(FE.normalizeFeedbackEndpoint("not a url", DEFAULT) === DEFAULT, "invalid URL was not reverted");
assert(FE.normalizeFeedbackEndpoint("", DEFAULT) === DEFAULT, "empty value did not fall back to default");
assert(FE.normalizeFeedbackEndpoint("http://localhost.evil.com/x", DEFAULT) === DEFAULT, "look-alike domain was not reverted");

console.log(`${passed}/${passed} feedback endpoint (loopback pinning) cases passed.`);
