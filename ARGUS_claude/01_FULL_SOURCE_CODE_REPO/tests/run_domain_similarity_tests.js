"use strict";

// Coverage for the offline brand-lookalike detector (P2). Verifies homoglyph,
// typosquat, and combosquat detection AND the false-positive guards (the brand
// itself, its subdomains, and unrelated legitimate domains must NOT be flagged).
const S = require("../engine/domain_similarity.js");
const Shared = require("../engine/shared_lists.js");

const BRANDS = Shared.LOOKALIKE_BRANDS;
const OPTS = { multiLabelSuffixes: Shared.MULTI_LABEL_SUFFIXES };

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}
const analyze = (host) => S.analyze(host, BRANDS, OPTS);

// skeleton folding.
assert(S.skeleton("PayPa1") === "paypal", "leet skeleton (1->l) failed");
assert(S.skeleton("gооgle") === "google", "cyrillic skeleton failed");
assert(S.skeleton("arnazon") === "amazon", "rn->m visual fold failed");

// editDistance sanity.
assert(S.editDistance("google", "gogle") === 1, "edit distance wrong");
assert(S.editDistance("paypal", "paypal") === 0, "identical strings not distance 0");

// HOMOGLYPH (high precision).
assert(analyze("paypa1.com").kind === "HOMOGLYPH", "paypa1.com not detected as homoglyph");
assert(analyze("gооgle.com").kind === "HOMOGLYPH", "cyrillic google not detected as homoglyph");
assert(analyze("аpple.com").kind === "HOMOGLYPH", "cyrillic apple not detected as homoglyph");
assert(analyze("arnazon.com").brand === "amazon.com", "arnazon.com not mapped to amazon");

// TYPOSQUAT.
assert(analyze("gogle.com").kind === "TYPOSQUAT", "gogle.com not detected as typosquat");
assert(analyze("paypall.com").kind === "TYPOSQUAT", "paypall.com not detected as typosquat");
assert(analyze("netfliix.com").kind === "TYPOSQUAT", "netfliix.com not detected as typosquat");

// COMBOSQUAT (brand as a whole token on an unrelated registrable domain).
assert(analyze("paypal.login-secure.tk").kind === "COMBOSQUAT", "paypal combosquat not detected");
assert(analyze("secure-kbank.verify-th.com").kind === "COMBOSQUAT", "kbank combosquat not detected");

// FALSE-POSITIVE GUARDS — none of these may be flagged.
for (const legit of [
  "paypal.com", "www.paypal.com", "checkout.paypal.com", "google.com", "mail.google.com",
  "apple.com", "kbank.co.th", "netflix.com",
  "example.com", "myblog.org", "applesauce-recipes.com", "networking-news.com",
  "thegoogleplex-museum.org", "supportdesk.example.com"
]) {
  assert(analyze(legit).match === false, `false positive: ${legit} was flagged as ${analyze(legit).kind}`);
}

// A raw IP or an empty host is never a lookalike.
assert(analyze("203.0.113.9").match === false, "raw IP flagged as lookalike");
assert(analyze("").match === false, "empty host flagged");

console.log(`${passed}/${passed} domain similarity cases passed.`);
