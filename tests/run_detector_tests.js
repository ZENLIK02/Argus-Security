"use strict";

const fs = require("fs");
const path = require("path");
const ArgusEngine = require("../engine/argus_engine.js");

const root = path.resolve(__dirname, "..");
const policy = JSON.parse(fs.readFileSync(path.join(root, "engine", "detection_policy.json"), "utf8"));
const categories = JSON.parse(fs.readFileSync(path.join(root, "risky_categories.json"), "utf8"));

function baseline(overrides) {
  return {
    url: "https://example.test/",
    domain: "example.test",
    pathname: "/",
    isTrustedDomain: false,
    isSearchEnginePage: false,
    hasPasswordField: false,
    hasOTP: false,
    hasLoginKeyword: false,
    apkLinks: [],
    foundStoreKeywords: [],
    suspiciousDomainSignals: [],
    foundGamblingKeywords: [],
    foundAdultKeywords: [],
    foundBankingKeywords: [],
    foundInvestmentKeywords: [],
    foundTechSupportKeywords: [],
    foundPopupAbuseKeywords: [],
    foundFakeShoppingKeywords: [],
    foundPrizeKeywords: [],
    foundPiratedKeywords: [],
    domainCategorySignals: { gambling: [], adult: [] },
    hasAdHeavySignal: false,
    dataLeakSignals: {
      crossDomainFormActionCount: 0,
      httpFormActionCount: 0,
      passwordCrossDomainForm: false,
      otpOrPaymentCrossDomainForm: false,
      passwordHttpForm: false,
      otpOrPaymentHttpForm: false,
      hiddenIframeCount: 0,
      externalScriptCount: 0,
      thirdPartyApkLinks: [],
      httpApkLinks: [],
      credentialLikeTextFieldCount: 0,
      sensitiveTextareaCount: 0,
      scriptNetworkSinkCount: 0,
      dynamicEndpointAssemblyCount: 0,
      externalUrlHints: [],
      delayedRelayIndicator: false,
      popupMessageTrapIndicator: false,
      clipboardReadIndicator: false,
      fileMetadataHarvestIndicator: false,
      guardedNetworkToggleIndicator: false,
      localFormWithJsSinkIndicator: false
    },
    networkSignals: {
      thirdPartyRequests: 0,
      thirdPartyXHRRequests: 0,
      insecureHttpRequests: 0,
      requestsAfterFormSubmit: 0,
      requestsAfterPasswordFocus: 0,
      temporalSignals: {
        formSubmitThenThirdPartyCount: 0,
        passwordFocusThenThirdPartyCount: 0,
        formSubmitThenCrossDomainRedirectCount: 0,
        downloadAfterFormSubmitCount: 0,
        recentEventTypes: []
      }
    },
    ...overrides
  };
}

function mergeSignals(base, overrides) {
  return baseline({
    ...overrides,
    dataLeakSignals: { ...base.dataLeakSignals, ...(overrides.dataLeakSignals || {}) },
    networkSignals: {
      ...base.networkSignals,
      ...(overrides.networkSignals || {}),
      temporalSignals: {
        ...base.networkSignals.temporalSignals,
        ...((overrides.networkSignals && overrides.networkSignals.temporalSignals) || {})
      }
    }
  });
}

const base = baseline({});
const cases = [
  {
    name: "plain safe page",
    signals: base,
    expect: { level: "SAFE", max: 10 }
  },
  {
    name: "Google Search false-positive guard",
    signals: mergeSignals(base, {
      url: "https://www.google.com/search?q=download+app",
      domain: "www.google.com",
      pathname: "/search",
      isTrustedDomain: true,
      isSearchEnginePage: true,
      hasLoginKeyword: true,
      foundStoreKeywords: ["Google Play"]
    }),
    expect: { level: "SAFE", max: 0 }
  },
  {
    name: "trusted site with normal password field",
    signals: mergeSignals(base, {
      domain: "accounts.google.com",
      isTrustedDomain: true,
      hasPasswordField: true,
      hasLoginKeyword: true
    }),
    expect: { level: "SAFE", max: 20 }
  },
  {
    name: "download app text without APK href",
    signals: mergeSignals(base, {
      foundStoreKeywords: ["Play Store"],
      hasLoginKeyword: false,
      apkLinks: []
    }),
    expect: { level: "SAFE", max: 34 }
  },
  {
    name: "fake store full flow",
    signals: mergeSignals(base, {
      hasPasswordField: true,
      hasOTP: true,
      hasLoginKeyword: true,
      foundStoreKeywords: ["Google Play", "Play Store"],
      apkLinks: ["https://downloads.bad.test/update.apk"]
    }),
    expect: { level: "HIGH_RISK", category: "FAKE_APP_STORE", min: 70 }
  },
  {
    name: "fake bank full flow",
    signals: mergeSignals(base, {
      hasPasswordField: true,
      hasOTP: true,
      hasLoginKeyword: true,
      foundBankingKeywords: ["online banking", "verify account"]
    }),
    expect: { level: "HIGH_RISK", category: "FAKE_BANKING", min: 70 }
  },
  {
    name: "gambling content only",
    signals: mergeSignals(base, {
      foundGamblingKeywords: ["casino", "bet"],
      domainCategorySignals: { gambling: ["casino"], adult: [] }
    }),
    expect: { level: "SUSPICIOUS", category: "CONTENT_RISK", min: 35, max: 55 }
  },
  {
    name: "adult content only",
    signals: mergeSignals(base, {
      foundAdultKeywords: ["adult", "18+"]
    }),
    expect: { level: "SUSPICIOUS", category: "CONTENT_RISK", min: 35, max: 55 }
  },
  {
    name: "cross-domain password form",
    signals: mergeSignals(base, {
      hasPasswordField: true,
      hasLoginKeyword: true,
      dataLeakSignals: { crossDomainFormActionCount: 1, passwordCrossDomainForm: true }
    }),
    expect: { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 70 }
  },
  {
    name: "insecure password and OTP form",
    signals: mergeSignals(base, {
      hasPasswordField: true,
      hasOTP: true,
      dataLeakSignals: { httpFormActionCount: 1, passwordHttpForm: true, otpOrPaymentHttpForm: true }
    }),
    expect: { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 70 }
  },
  {
    name: "quiet profile sync evasive relay",
    signals: mergeSignals(base, {
      dataLeakSignals: {
        credentialLikeTextFieldCount: 2,
        localFormWithJsSinkIndicator: true,
        scriptNetworkSinkCount: 2,
        dynamicEndpointAssemblyCount: 1,
        externalUrlHints: ["https://relay.invalid/collect"],
        delayedRelayIndicator: true,
        guardedNetworkToggleIndicator: true
      }
    }),
    expect: { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 70 }
  },
  {
    name: "consent mirror popup relay",
    signals: mergeSignals(base, {
      dataLeakSignals: {
        scriptNetworkSinkCount: 2,
        externalUrlHints: ["https://relay.invalid/consent"],
        popupMessageTrapIndicator: true,
        dynamicEndpointAssemblyCount: 1,
        guardedNetworkToggleIndicator: true
      }
    }),
    expect: { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 70 }
  },
  {
    name: "clipboard vault secret relay",
    signals: mergeSignals(base, {
      dataLeakSignals: {
        sensitiveTextareaCount: 1,
        clipboardReadIndicator: true,
        fileMetadataHarvestIndicator: true,
        scriptNetworkSinkCount: 1,
        dynamicEndpointAssemblyCount: 1,
        externalUrlHints: ["https://relay.invalid/vault"]
      }
    }),
    expect: { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 70 }
  },
  {
    name: "temporal exfiltration sequence",
    signals: mergeSignals(base, {
      networkSignals: {
        thirdPartyRequests: 5,
        thirdPartyXHRRequests: 4,
        requestsAfterFormSubmit: 4,
        temporalSignals: {
          formSubmitThenThirdPartyCount: 4,
          formSubmitThenCrossDomainRedirectCount: 1,
          recentEventTypes: ["FORM_SUBMIT", "THIRD_PARTY_AFTER_FORM", "CROSS_DOMAIN_REDIRECT_AFTER_FORM"]
        }
      }
    }),
    expect: { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 70 }
  },
  {
    name: "ad-heavy page without credential theft",
    signals: mergeSignals(base, {
      hasAdHeavySignal: true,
      foundPopupAbuseKeywords: ["allow notifications"]
    }),
    expect: { level: "SUSPICIOUS", category: "MALVERTISING", min: 35, max: 69 }
  }
];

let failures = 0;
for (const testCase of cases) {
  const result = ArgusEngine.evaluate(testCase.signals, categories, policy);
  const errors = [];
  if (testCase.expect.level && result.level !== testCase.expect.level) errors.push(`level ${result.level}`);
  if (testCase.expect.category && result.category !== testCase.expect.category) errors.push(`category ${result.category}`);
  if (Number.isFinite(testCase.expect.min) && result.score < testCase.expect.min) errors.push(`score ${result.score} < ${testCase.expect.min}`);
  if (Number.isFinite(testCase.expect.max) && result.score > testCase.expect.max) errors.push(`score ${result.score} > ${testCase.expect.max}`);
  if (!Array.isArray(result.toolResults) || result.toolResults.length < 7) errors.push("missing tool results");
  if (!Number.isFinite(result.confidence)) errors.push("missing confidence");

  if (errors.length > 0) {
    failures += 1;
    console.error(`FAIL ${testCase.name}: ${errors.join(", ")}`);
  } else {
    console.log(`PASS ${testCase.name}: ${result.score} ${result.level} ${result.category} confidence=${result.confidence}`);
  }
}

console.log(`\n${cases.length - failures}/${cases.length} detector cases passed (policy ${policy.version}).`);
if (failures > 0) {
  process.exitCode = 1;
}
