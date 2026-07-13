"use strict";

// Regression coverage for the de-duplicated domain/category configuration (F8):
// content.js and service_worker.js must consume the single ArgusSharedLists source
// instead of re-declaring their own diverging copies.
const fs = require("fs");
const path = require("path");
const Shared = require("../engine/shared_lists.js");

const root = path.resolve(__dirname, "..");
const content = fs.readFileSync(path.join(root, "content.js"), "utf8");
const worker = fs.readFileSync(path.join(root, "service_worker.js"), "utf8");

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

// The shared module is the source of truth and is a superset of both prior lists.
assert(Shared.TRUSTED_DOMAINS.includes("google.com"), "shared trusted list missing google.com");
assert(Shared.TRUSTED_DOMAINS.includes("bing.com"), "shared trusted list missing bing.com (was JSON-only)");
assert(Shared.TRUSTED_DOMAINS.includes("f-droid.org") && Shared.TRUSTED_DOMAINS.includes("wikipedia.org"), "shared trusted list lost former JSON entries");
assert(Shared.TRUSTED_DOMAINS.includes("kbank.co.th"), "shared trusted list lost former content.js entries");
assert(Shared.KNOWN_IDENTITY_DOMAINS.includes("accounts.google.com"), "shared identity list incomplete");
assert(Shared.KNOWN_PAYMENT_DOMAINS.includes("stripe.com"), "shared payment list incomplete");
assert(Shared.MULTI_LABEL_SUFFIXES.includes("co.th"), "shared multi-label suffixes incomplete");
assert(Shared.SUSPICIOUS_DOMAIN_WORDS.includes("verify") && Shared.SUSPICIOUS_DOMAIN_WORDS.includes("apk"), "shared suspicious words are not the content superset");
assert(Shared.GAMBLING_DOMAIN_PATTERNS.includes("casino"), "shared gambling patterns incomplete");
assert(Shared.ADULT_DOMAIN_PATTERNS.includes("porn"), "shared adult patterns incomplete");
assert(Array.isArray(Shared.KEYWORDS.gambling) && Shared.KEYWORDS.gambling.includes("casino"), "shared keyword taxonomy incomplete");
assert(Shared.SEARCH_ENGINE_DOMAINS.includes("duckduckgo.com"), "shared search-engine list incomplete");

// No duplicate declarations remain: both files reference the shared module and no
// longer inline their own large list literals.
assert(content.includes("ArgusSharedLists"), "content.js does not consume ArgusSharedLists");
assert(worker.includes("ArgusSharedLists") || worker.includes("SHARED_LISTS"), "service_worker.js does not consume ArgusSharedLists");
assert(!/const TRUSTED_DOMAINS = \[\s*\n\s*"google\.com"/.test(content), "content.js still inlines its own TRUSTED_DOMAINS literal");
assert(!/const KEYWORDS = \{\s*\n\s*otp:/.test(content), "content.js still inlines its own KEYWORDS literal");
assert(!/const KNOWN_IDENTITY_DOMAINS = \["accounts\.google\.com"/.test(worker), "service_worker.js still inlines its own KNOWN_IDENTITY_DOMAINS literal");
assert(!/const suspiciousWords = \["verify"/.test(worker), "service_worker.js still inlines its own suspicious-word literal");

// trusted_domains.json is now an optional additions file (baseline moved to shared).
const trusted = JSON.parse(fs.readFileSync(path.join(root, "trusted_domains.json"), "utf8"));
assert(Array.isArray(trusted), "trusted_domains.json must remain an array of optional additions");

console.log(`${passed}/${passed} shared config (F8 de-duplication) cases passed.`);
