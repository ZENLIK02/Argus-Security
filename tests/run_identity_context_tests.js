"use strict";

const fs = require("fs");
const path = require("path");
const Identity = require("../engine/brand_identity.js");
const Policy = require("../engine/evidence_decision_policy.js");

const root = path.resolve(__dirname, "..");
const registry = JSON.parse(fs.readFileSync(path.join(root, "engine", "brand_registry.json"), "utf8"));
let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

assert(Identity.validateRegistry(registry), "bundled brand registry is invalid");
assert(Identity.getRegistrableDomain("secure.kbank.co.th") === "kbank.co.th", "Thai public-suffix handling is incorrect");
assert(Identity.getRegistrableDomain("login.example.com.br", new Set(registry.multiLabelPublicSuffixes)) === "example.com.br", "multi-region public-suffix snapshot is not applied");

const official = Identity.analyze({ domain: "secure.kbank.co.th", identityTextSurface: "KBank mobile banking login" }, registry);
assert(official.officialDomain && !official.domainMismatch, "official KBank domain was treated as impersonation");

const fakeBank = Identity.analyze({ domain: "kbank-secure-login.example", identityTextSurface: "KBank mobile banking login" }, registry);
assert(fakeBank.domainMismatch && fakeBank.primaryContext === "BANKING_LENDING", "fake KBank identity mismatch was missed");

const deceptive = Identity.analyze({ domain: "kbank.co.th.attacker.example", identityTextSurface: "KBank verify account" }, registry);
assert(deceptive.domainMismatch && deceptive.deceptiveSubdomain, "deceptive official-domain subdomain was missed");

const genericBank = Identity.analyze({ domain: "new-loan.example", identityTextSurface: "mobile banking loan credit approval" }, registry);
assert(genericBank.highValueContext && genericBank.claimedBrandIds.length === 0, "generic high-value banking context was not separated from a brand claim");

const appleArticle = Identity.analyze({ domain: "technology-news.example", identityTextSurface: "Apple announces a new product" }, registry);
assert(appleArticle.domainMismatch && !appleArticle.strongMismatch, "ordinary brand news was treated as a strong identity claim");

const visualRegistry = JSON.parse(JSON.stringify(registry));
visualRegistry.brands.find((brand) => brand.brandId === "kbank").visualHashes = ["0123456789abcdef"];
const visual = Identity.analyze({ domain: "not-kbank.example", identityTextSurface: "KBank", visualHashes: ["0123456789abcdee"] }, visualRegistry);
assert(visual.visualMatch, "near perceptual-hash match was missed");
assert(Identity.hammingHex("0000000000000000", "000000000000000f") === 4, "visual Hamming distance is incorrect");

const finding = (id, category = "BRAND_IMPERSONATION") => ({ id, category, tool: "TEST", confidence: 0.9 });
function decide(evidence, identitySignals, sensitivityMode, sensitiveInteractionObserved = false) {
  return Policy.decide({
    legacyRisk: { score: 50, evidence, modelAnalysis: { score: 50 } },
    context: { scanPhase: "FINAL", identitySignals, sensitivityMode, sensitiveInteractionObserved, reputation: { verdict: "UNKNOWN" } }
  });
}

const mismatchEvidence = [finding("CLAIMED_BRAND_IDENTITY"), finding("DOMAIN_IDENTITY_MISMATCH")];
const conservative = decide(mismatchEvidence, fakeBank, "CONSERVATIVE");
assert(conservative.status === "MONITORING" && !conservative.warningAllowed, "Conservative mode warned without sensitive action");

const balanced = decide(mismatchEvidence, fakeBank, "BALANCED");
assert(balanced.status === "RISKY_CONTEXT" && balanced.warningStage === "BADGE", "Balanced mode did not create the first-stage mismatch badge");

const protective = decide([finding("HIGH_VALUE_CONTEXT", "BANKING_LENDING")], genericBank, "PROTECTIVE");
assert(protective.status === "RISKY_CONTEXT", "Protective mode did not caution on a high-value context");

const surfaceBeforeInteraction = decide(mismatchEvidence.concat(finding("SENSITIVE_ACTION_SURFACE", "SENSITIVE_ACTION")), fakeBank, "BALANCED", false);
assert(surfaceBeforeInteraction.status === "RISKY_CONTEXT" && surfaceBeforeInteraction.warningStage === "BADGE", "sensitive surface expanded before user interaction");

const interaction = decide(mismatchEvidence.concat(finding("SENSITIVE_ACTION_SURFACE", "SENSITIVE_ACTION")), fakeBank, "BALANCED", true);
assert(interaction.status === "RISKY_CONTEXT" && interaction.warningStage === "INTERACTION", "sensitive interaction did not expand the context warning");

const suspicious = decide(mismatchEvidence.concat(finding("SENSITIVE_ACTION_SURFACE", "SENSITIVE_ACTION"), finding("URL_OBFUSCATION")), fakeBank, "BALANCED", true);
assert(suspicious.status === "SUSPICIOUS", "mismatch, sensitive action, and independent domain risk did not correlate");

const officialDecision = decide([finding("CLAIMED_BRAND_IDENTITY"), finding("HIGH_VALUE_CONTEXT", "BANKING_LENDING")], official, "PROTECTIVE");
assert(officialDecision.status === "SAFE", "official brand domain did not receive the identity trust guard");

console.log(`${passed}/${passed} identity and risk-context cases passed.`);
