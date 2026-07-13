"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const seeds = JSON.parse(fs.readFileSync(path.join(root, "datasets", "phiusiil_balanced_url_seeds.json"), "utf8"));
const core = JSON.parse(fs.readFileSync(path.join(root, "datasets", "exfiltration_eval_cases.json"), "utf8"));
const trustedDomains = JSON.parse(fs.readFileSync(path.join(root, "trusted_domains.json"), "utf8"));
const outputPath = path.join(root, "datasets", "randomized_web_eval_cases.json");
const template = core.cases.find((testCase) => testCase.id === "safe-static-https").signals;
const random = mulberry32(0xA46F2026);

const safeSeeds = shuffle(seeds.records.filter((record) => record.label === "SAFE"), random);
const phishingSeeds = shuffle(seeds.records.filter((record) => record.label === "PHISHING"), random);
if (safeSeeds.length !== 500 || phishingSeeds.length !== 500) {
  throw new Error(`Expected 500 SAFE and 500 PHISHING seeds; got ${safeSeeds.length}/${phishingSeeds.length}.`);
}

const cases = [];
safeSeeds.forEach((seed, index) => cases.push(makeSafeCase(seed, index)));
phishingSeeds.forEach((seed, index) => cases.push(makePhishingCase(seed, index)));

if (cases.length !== 1000 || new Set(cases.map((testCase) => testCase.id)).size !== 1000) {
  throw new Error(`Expected 1000 unique randomized cases; generated ${cases.length}.`);
}

const corpus = {
  name: "Project Argus Randomized Real-vs-Fake Website Corpus",
  version: "1.0.0",
  randomSeed: "0xA46F2026",
  generatedAt: "2026-07-10",
  composition: { safe: 500, fake: 500, folds: 5 },
  privacy: "Uses sanitized public URL metadata plus synthetic browser-observable behavior. No query strings, credentials, payloads, cookies, or live malicious code.",
  sourceSummary: [
    "UCI PhiUSIIL legitimate and phishing URL labels",
    "Randomized privacy-safe browser behavior variants",
    "Five deterministic stratified folds for out-of-fold evaluation"
  ],
  cases
};

fs.writeFileSync(outputPath, `${JSON.stringify(corpus, null, 2)}\n`, "utf8");
console.log(`Generated ${cases.length} randomized cases (500 SAFE / 500 fake) at ${outputPath}`);

function makeSafeCase(seed, index) {
  const family = index % 10;
  const signals = seedSignals(seed);
  const secure = secureHeaders();
  const small = randomInt(1, 4);
  signals.securitySignals = { ...signals.securitySignals, ...secure };

  if (family === 0) {
    Object.assign(signals, { hasPasswordField: true, hasOTP: chance(0.55), hasLoginKeyword: true });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1 });
    Object.assign(signals.networkSignals, { totalRequests: randomInt(5, 20), writeRequests: 1, writeRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1 });
  } else if (family === 1) {
    Object.assign(signals, { hasPasswordField: chance(0.5), hasOTP: true, hasLoginKeyword: true });
    signals.suspiciousDomainSignals = signals.suspiciousDomainSignals.slice(0, 1);
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1, externalScriptCount: small });
  } else if (family === 2) {
    Object.assign(signals, { hasPasswordField: chance(0.15), hasOTP: chance(0.15), foundBankingKeywords: chance(0.4) ? ["payment"] : [] });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1, externalScriptCount: randomInt(1, 5), thirdPartyIframeCount: chance(0.5) ? 1 : 0 });
    Object.assign(signals.networkSignals, { totalRequests: randomInt(12, 40), thirdPartyRequests: randomInt(2, 10), writeRequests: 1 });
  } else if (family === 3) {
    Object.assign(signals, { hasPasswordField: false, hasOTP: false, hasLoginKeyword: false, pageProtocol: "http:", url: signals.url.replace(/^https:/, "http:") });
    Object.assign(signals.dataLeakSignals, { formCount: 1, httpFormActionCount: 1, sensitiveFormCount: 0 });
    Object.assign(signals.networkSignals, { insecureHttpRequests: randomInt(2, 12), writeRequests: 1, insecureWriteRequests: 1 });
  } else if (family === 4) {
    signals.hasAdHeavySignal = true;
    if (chance(0.5)) {
      signals.foundGamblingKeywords = ["casino", "bet"];
      signals.domainCategorySignals.gambling = ["bet"];
    } else {
      signals.foundAdultKeywords = ["adult", "18+"];
      signals.domainCategorySignals.adult = ["adult"];
    }
  } else if (family === 5) {
    signals.foundStoreKeywords = ["Install App", "download app"];
    if (signals.isTrustedDomain && chance(0.5)) signals.apkLinks = [{ href: `${signals.url.replace(/\/$/, "")}/release.apk` }];
  } else if (family === 6) {
    const mode = randomInt(0, 6);
    signals.dataLeakSignals.formValueReadIndicator = mode === 0;
    signals.dataLeakSignals.formDataReadIndicator = mode === 1;
    signals.dataLeakSignals.sensitiveStorageWriteIndicator = mode === 2;
    signals.dataLeakSignals.cookieReadIndicator = mode === 3;
    signals.dataLeakSignals.encodedPayloadIndicator = mode === 4;
    signals.dataLeakSignals.webSocketSendIndicator = mode === 5;
    signals.dataLeakSignals.wildcardPostMessageIndicator = mode === 6;
  } else if (family === 7) {
    Object.assign(signals.networkSignals, {
      totalRequests: randomInt(20, 80), thirdPartyRequests: randomInt(8, 25), thirdPartyScriptRequests: randomInt(2, 8),
      thirdPartyXHRRequests: randomInt(1, 5), writeRequests: randomInt(1, 4), thirdPartyWriteRequests: randomInt(1, 3)
    });
  } else if (family === 8) {
    Object.assign(signals.dataLeakSignals, { externalScriptCount: randomInt(2, 8), thirdPartyIframeCount: randomInt(0, 3) });
    Object.assign(signals.securitySignals, {
      responseHeadersObserved: true, missingSecurityHeaderCount: randomInt(2, 5),
      thirdPartyScriptWithoutIntegrityCount: randomInt(2, 6), unsandboxedThirdPartyIframeCount: randomInt(0, 2),
      mixedContentRequestCount: chance(0.4) ? 1 : 0, insecureActiveContentRequestCount: 0
    });
  } else {
    Object.assign(signals.networkSignals, { totalRequests: randomInt(0, 60), thirdPartyRequests: randomInt(0, 15) });
  }

  return makeCase(`random-safe-${String(index + 1).padStart(3, "0")}`, "SAFE", family, index, signals, { level: "SAFE", max: 34, targetScore: randomInt(4, 18) });
}

function makePhishingCase(seed, index) {
  const family = index % 10;
  const signals = seedSignals(seed);
  signals.isTrustedDomain = false;
  signals.hasLoginKeyword = true;
  const endpoint = `https://relay-${randomInt(1000, 9999)}.invalid/collect`;
  let expect;

  if (family === 0) {
    Object.assign(signals, { hasPasswordField: true, hasOTP: chance(0.45), hasLoginKeyword: true });
    Object.assign(signals.urlLexicalSignals, { hasObfuscation: true, excessiveSubdomainCount: Math.max(2, signals.urlLexicalSignals.excessiveSubdomainCount), credentialPathWordCount: Math.max(1, signals.urlLexicalSignals.credentialPathWordCount), lexicalRiskCount: Math.max(3, signals.urlLexicalSignals.lexicalRiskCount) });
    signals.suspiciousDomainSignals = [];
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1 });
    expect = { level: "SUSPICIOUS", min: 35, max: 69, targetScore: randomInt(44, 60) };
  } else if (family === 1) {
    Object.assign(signals, { hasPasswordField: true, hasOTP: true, foundBankingKeywords: ["verify bank account", "account locked"] });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1 });
    expect = high("FAKE_BANKING");
  } else if (family === 2) {
    const apk = `http://download-${randomInt(100, 999)}.invalid/security.apk`;
    Object.assign(signals, { foundStoreKeywords: ["Google Play", "Play Store"], apkLinks: [{ href: apk }] });
    Object.assign(signals.dataLeakSignals, { thirdPartyApkLinks: [apk], httpApkLinks: [apk] });
    expect = high("MALICIOUS_APK");
  } else if (family === 3) {
    Object.assign(signals, { hasPasswordField: chance(0.5), hasOTP: true });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1, crossDomainFormActionCount: 1, passwordCrossDomainForm: signals.hasPasswordField, otpOrPaymentCrossDomainForm: !signals.hasPasswordField });
    expect = high("DATA_EXFILTRATION");
  } else if (family === 4) {
    Object.assign(signals, { hasPasswordField: chance(0.5), hasOTP: true, pageProtocol: "http:", url: signals.url.replace(/^https:/, "http:") });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1, httpFormActionCount: 1, passwordHttpForm: signals.hasPasswordField, otpOrPaymentHttpForm: true, httpPageWithSensitiveForm: true });
    expect = high("INSECURE_FORM_SUBMISSION");
  } else if (family === 5) {
    Object.assign(signals, { hasPasswordField: true });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1, formValueReadIndicator: true, formDataReadIndicator: chance(0.5), scriptNetworkSinkCount: randomInt(1, 3), externalUrlHints: [endpoint], localFormWithJsSinkIndicator: true });
    expect = suspicious("DATA_EXFILTRATION");
  } else if (family === 6) {
    Object.assign(signals.dataLeakSignals, { sensitiveStorageWriteIndicator: true, cookieReadIndicator: chance(0.7), encodedPayloadIndicator: chance(0.5), scriptNetworkSinkCount: randomInt(1, 3), externalUrlHints: [endpoint] });
    expect = suspicious("DATA_EXFILTRATION");
  } else if (family === 7) {
    Object.assign(signals, { hasPasswordField: chance(0.5), hasOTP: true });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1 });
    Object.assign(signals.securitySignals, { responseHeadersObserved: true, missingSecurityHeaderCount: randomInt(2, 5), mixedContentRequestCount: randomInt(1, 4), insecureActiveContentRequestCount: randomInt(1, 3) });
    expect = high("INSECURE_FORM_SUBMISSION");
  } else if (family === 8) {
    Object.assign(signals, { hasPasswordField: chance(0.5), hasOTP: true });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1 });
    Object.assign(signals.networkSignals, {
      totalRequests: randomInt(1, 6), writeRequests: 1, insecureWriteRequests: chance(0.5) ? 1 : 0,
      writeRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1,
      insecureSensitiveWriteRequests: chance(0.5) ? 1 : 0, crossDomainSensitiveWriteRequests: 1
    });
    expect = high();
  } else {
    Object.assign(signals, { hasPasswordField: true });
    Object.assign(signals.dataLeakSignals, { formCount: 1, sensitiveFormCount: 1 });
    Object.assign(signals.networkSignals, {
      totalRequests: randomInt(3, 10), thirdPartyRequests: randomInt(3, 8), thirdPartyXHRRequests: randomInt(3, 6), requestsAfterFormSubmit: randomInt(3, 7),
      temporalSignals: { ...signals.networkSignals.temporalSignals, formSubmitThenThirdPartyCount: randomInt(3, 7), formSubmitThenCrossDomainRedirectCount: 1 }
    });
    expect = high("DATA_EXFILTRATION");
  }

  return makeCase(`random-fake-${String(index + 1).padStart(3, "0")}`, "FAKE", family, index, signals, expect);
}

function seedSignals(seed) {
  const signals = JSON.parse(JSON.stringify(template));
  Object.assign(signals, {
    url: seed.url, domain: seed.domain, pathname: seed.pathname, pageProtocol: seed.pageProtocol,
    isTrustedDomain: trustedDomains.some((domain) => seed.domain === domain || seed.domain.endsWith(`.${domain}`)),
    urlLexicalSignals: lexicalSignals(seed)
  });
  signals.suspiciousDomainSignals = lexicalReasons(signals.urlLexicalSignals);
  return signals;
}

function lexicalSignals(seed) {
  const feature = seed.features || {};
  const domain = String(seed.domain || "");
  const pathname = String(seed.pathname || "");
  const digitCount = (domain.match(/\d/g) || []).length;
  const hyphenCount = (domain.match(/-/g) || []).length;
  const credentialPathWordCount = (pathname.toLowerCase().match(/login|signin|verify|account|auth|secure|wallet|bank/g) || []).length;
  const excessiveSubdomainCount = Math.max(0, Number(feature.NoOfSubDomain || 0) - 2);
  const hasObfuscation = Number(feature.HasObfuscation || 0) > 0 || Number(feature.NoOfObfuscatedChar || 0) >= 2;
  const domainDigitRatio = digitCount / Math.max(1, domain.length);
  const hasAtSymbol = String(seed.url || "").includes("@");
  const lexicalRiskCount = [
    Number(feature.IsDomainIP || 0) > 0, Number(feature.URLLength || 0) >= 100, excessiveSubdomainCount >= 2,
    hasObfuscation, domainDigitRatio >= 0.25, hyphenCount >= 3, credentialPathWordCount >= 1, hasAtSymbol
  ].filter(Boolean).length;
  return {
    urlLength: Number(feature.URLLength || seed.url.length), domainLength: Number(feature.DomainLength || domain.length),
    isDomainIP: Number(feature.IsDomainIP || 0) > 0, subdomainCount: Number(feature.NoOfSubDomain || 0), excessiveSubdomainCount,
    hasObfuscation, obfuscatedCharCount: Number(feature.NoOfObfuscatedChar || 0), domainDigitRatio,
    hyphenCount, credentialPathWordCount, hasAtSymbol, lexicalRiskCount
  };
}

function lexicalReasons(lexical) {
  const reasons = [];
  if (lexical.isDomainIP) reasons.push("URL uses an IP-address host.");
  if (lexical.hasObfuscation) reasons.push("URL contains obfuscation indicators.");
  if (lexical.excessiveSubdomainCount >= 2) reasons.push("URL contains many nested subdomains.");
  if (lexical.domainDigitRatio >= 0.25) reasons.push("Domain contains an unusually high digit ratio.");
  if (lexical.credentialPathWordCount >= 1) reasons.push("URL path contains credential-related wording.");
  return reasons;
}

function makeCase(id, label, family, index, signals, expect) {
  return { id, label, family: `${label.toLowerCase()}-${family}`, fold: index % 5, signals, expect, sourceTags: ["UCI_PHIUSIIL", "SEEDED_RANDOMIZATION"] };
}

function high(category) {
  return { level: "HIGH_RISK", ...(category ? { category } : {}), min: 70, targetScore: randomInt(80, 94) };
}

function suspicious(category) {
  return { level: "SUSPICIOUS", category, min: 35, max: 69, targetScore: randomInt(46, 60) };
}

function secureHeaders() {
  return { responseHeadersObserved: true, hasContentSecurityPolicy: true, hasStrictTransportSecurity: true, hasXContentTypeOptions: true, hasReferrerPolicy: true, hasPermissionsPolicy: true, missingSecurityHeaderCount: 0 };
}

function chance(probability) {
  return random() < probability;
}

function randomInt(minimum, maximum) {
  return Math.floor(random() * (maximum - minimum + 1)) + minimum;
}

function shuffle(values, rng) {
  const result = values.slice();
  for (let index = result.length - 1; index > 0; index -= 1) {
    const target = Math.floor(rng() * (index + 1));
    [result[index], result[target]] = [result[target], result[index]];
  }
  return result;
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function mulberry32(seed) {
  return function next() {
    let value = seed += 0x6D2B79F5;
    value = Math.imul(value ^ value >>> 15, value | 1);
    value ^= value + Math.imul(value ^ value >>> 7, value | 61);
    return ((value ^ value >>> 14) >>> 0) / 4294967296;
  };
}
