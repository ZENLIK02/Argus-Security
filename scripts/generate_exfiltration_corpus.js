"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const outputPath = path.join(root, "datasets", "exfiltration_eval_cases.json");

function baseline() {
  return {
    url: "https://example.test/",
    domain: "example.test",
    pathname: "/",
    pageProtocol: "https:",
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
      formCount: 0,
      sensitiveFormCount: 0,
      crossDomainFormActionCount: 0,
      httpFormActionCount: 0,
      passwordCrossDomainForm: false,
      otpOrPaymentCrossDomainForm: false,
      passwordHttpForm: false,
      otpOrPaymentHttpForm: false,
      sameOriginSensitiveHttpForm: false,
      httpPageWithSensitiveForm: false,
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
      totalRequests: 0,
      thirdPartyRequests: 0,
      thirdPartyXHRRequests: 0,
      insecureHttpRequests: 0,
      writeRequests: 0,
      insecureWriteRequests: 0,
      requestsAfterFormSubmit: 0,
      requestsAfterPasswordFocus: 0,
      writeRequestsAfterFormSubmit: 0,
      insecureWriteRequestsAfterFormSubmit: 0,
      thirdPartyWriteRequestsAfterFormSubmit: 0,
      sensitiveWriteRequestsAfterFormSubmit: 0,
      insecureSensitiveWriteRequests: 0,
      crossDomainSensitiveWriteRequests: 0,
      beaconOrPingAfterSensitiveInput: 0,
      temporalSignals: {
        formSubmitThenThirdPartyCount: 0,
        passwordFocusThenThirdPartyCount: 0,
        formSubmitThenCrossDomainRedirectCount: 0,
        downloadAfterFormSubmitCount: 0,
        recentEventTypes: []
      }
    }
  };
}

function mergeSignals(overrides = {}) {
  const base = baseline();
  return {
    ...base,
    ...overrides,
    domainCategorySignals: {
      ...base.domainCategorySignals,
      ...(overrides.domainCategorySignals || {})
    },
    dataLeakSignals: {
      ...base.dataLeakSignals,
      ...(overrides.dataLeakSignals || {})
    },
    networkSignals: {
      ...base.networkSignals,
      ...(overrides.networkSignals || {}),
      temporalSignals: {
        ...base.networkSignals.temporalSignals,
        ...((overrides.networkSignals && overrides.networkSignals.temporalSignals) || {})
      }
    }
  };
}

const cases = [];
function add(id, group, overrides, expect, sourceTags) {
  cases.push({ id, group, signals: mergeSignals(overrides), expect, sourceTags });
}

const safeCases = [
  ["safe-static-https", {}],
  ["safe-trusted-login", { domain: "accounts.google.com", isTrustedDomain: true, hasPasswordField: true, hasLoginKeyword: true }],
  ["safe-google-search", { domain: "www.google.com", pathname: "/search", isTrustedDomain: true, isSearchEnginePage: true, hasLoginKeyword: true }],
  ["safe-secure-same-origin-post", { networkSignals: { writeRequests: 1, writeRequestsAfterFormSubmit: 1 } }],
  ["safe-cdn-assets", { networkSignals: { thirdPartyRequests: 12, thirdPartyXHRRequests: 0 } }],
  ["safe-http-text-only", { url: "http://example.test/", pageProtocol: "http:", networkSignals: { insecureHttpRequests: 4 } }],
  ["safe-normal-news-images", { hasAdHeavySignal: true }],
  ["safe-secure-password-submit", { hasPasswordField: true, networkSignals: { writeRequests: 1, writeRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1 } }]
];
safeCases.forEach(([id, signals]) => add(id, "benign-control", signals, { level: "SAFE", max: 15 }, ["BENIGN_CONTROL"]));

for (let index = 1; index <= 4; index += 1) {
  add(`content-gambling-${index}`, "content-low-priority", {
    domain: `slots${index}.example.test`,
    foundGamblingKeywords: ["casino", "betting", "slot"],
    domainCategorySignals: { gambling: ["slot"], adult: [] },
    hasAdHeavySignal: index % 2 === 0
  }, { level: "SAFE", max: 15 }, ["CONTENT_ONLY"]);
  add(`content-adult-${index}`, "content-low-priority", {
    domain: `adult${index}.example.test`,
    foundAdultKeywords: ["adult", "18+"],
    domainCategorySignals: { gambling: [], adult: ["adult"] },
    hasAdHeavySignal: index % 2 === 1
  }, { level: "SAFE", max: 15 }, ["CONTENT_ONLY"]);
}

const contextCases = [
  ["context-password-field", { hasPasswordField: true }],
  ["context-otp-field", { hasOTP: true }],
  ["context-login-language", { hasLoginKeyword: true }],
  ["context-password-otp", { hasPasswordField: true, hasOTP: true }],
  ["context-full-login-flow", { hasPasswordField: true, hasOTP: true, hasLoginKeyword: true }],
  ["context-bank-language", { hasPasswordField: true, hasOTP: true, foundBankingKeywords: ["bank", "verify account"] }],
  ["context-store-language", { foundStoreKeywords: ["Google Play", "Play Store"] }],
  ["context-store-with-apk", { foundStoreKeywords: ["Play Store"], apkLinks: [{ href: "https://download.example.test/app.apk" }] }],
  ["context-risk-domain", { domain: "secure-login-update.example.test", suspiciousDomainSignals: ["Domain contains suspicious word: login."] }],
  ["context-lookalike-domain", { domain: "paypa1-account.example.test" }],
  ["context-clipboard-only", { dataLeakSignals: { clipboardReadIndicator: true } }],
  ["context-file-metadata-only", { dataLeakSignals: { fileMetadataHarvestIndicator: true } }]
];
contextCases.forEach(([id, signals]) => add(id, "context-low-priority", signals, { level: "SAFE", max: 34 }, ["CONTEXT_ONLY"]));

const directFormCases = [
  ["form-http-password", { url: "http://example.test/login", pageProtocol: "http:", hasPasswordField: true, dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, httpFormActionCount: 1, passwordHttpForm: true, sameOriginSensitiveHttpForm: true, httpPageWithSensitiveForm: true } }, { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 85 }],
  ["form-http-otp", { url: "http://example.test/verify", pageProtocol: "http:", hasOTP: true, dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, httpFormActionCount: 1, otpOrPaymentHttpForm: true, sameOriginSensitiveHttpForm: true, httpPageWithSensitiveForm: true } }, { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 85 }],
  ["form-http-payment", { url: "http://shop.example.test/pay", domain: "shop.example.test", pageProtocol: "http:", dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, httpFormActionCount: 1, otpOrPaymentHttpForm: true, sameOriginSensitiveHttpForm: true, httpPageWithSensitiveForm: true } }, { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 85 }],
  ["form-http-localhost-disguised-secret", { url: "http://localhost:8080/collect", domain: "localhost", pageProtocol: "http:", dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, httpFormActionCount: 1, sameOriginSensitiveHttpForm: true, httpPageWithSensitiveForm: true, credentialLikeTextFieldCount: 1 } }, { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 85 }],
  ["form-cross-domain-password", { hasPasswordField: true, dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, crossDomainFormActionCount: 1, passwordCrossDomainForm: true } }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }],
  ["form-cross-domain-otp", { hasOTP: true, dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, crossDomainFormActionCount: 1, otpOrPaymentCrossDomainForm: true } }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }],
  ["form-cross-domain-payment", { dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, crossDomainFormActionCount: 1, otpOrPaymentCrossDomainForm: true } }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }],
  ["form-cross-domain-disguised-secret", { dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, crossDomainFormActionCount: 1, credentialLikeTextFieldCount: 1 } }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }],
  ["form-http-generic-search", { url: "http://example.test/search", pageProtocol: "http:", dataLeakSignals: { formCount: 1, httpFormActionCount: 1 } }, { level: "SAFE", max: 20 }],
  ["form-cross-domain-generic-newsletter", { dataLeakSignals: { formCount: 1, crossDomainFormActionCount: 1 } }, { level: "SAFE", max: 25 }],
  ["form-https-local-sensitive", { hasPasswordField: true, dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 } }, { level: "SAFE", max: 34 }],
  ["form-trusted-https-sensitive", { domain: "accounts.google.com", isTrustedDomain: true, hasPasswordField: true, dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 } }, { level: "SAFE", max: 20 }]
];
directFormCases.forEach(([id, signals, expect]) => add(id, "direct-form-protection", signals, expect, ["OWASP_FORM_ACTION", "NIST_TLS"]));

for (let index = 1; index <= 4; index += 1) {
  add(`network-unencrypted-sensitive-write-${index}`, "observed-network", {
    url: index === 1 ? "http://localhost:8000/demo" : `http://leak${index}.example.test/collect`,
    domain: index === 1 ? "localhost" : `leak${index}.example.test`,
    pageProtocol: "http:",
    hasPasswordField: index % 2 === 0,
    hasOTP: index % 2 === 1,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, httpPageWithSensitiveForm: true },
    networkSignals: { totalRequests: 1, writeRequests: 1, insecureWriteRequests: 1, writeRequestsAfterFormSubmit: 1, insecureWriteRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1, insecureSensitiveWriteRequests: 1 }
  }, { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 90 }, ["MITRE_T1048_003", "NIST_TLS"]);

  add(`network-cross-domain-sensitive-write-${index}`, "observed-network", {
    hasPasswordField: index % 2 === 0,
    hasOTP: index % 2 === 1,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 },
    networkSignals: { totalRequests: 1, thirdPartyRequests: 1, thirdPartyXHRRequests: 1, writeRequests: 1, writeRequestsAfterFormSubmit: 1, thirdPartyWriteRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1, crossDomainSensitiveWriteRequests: 1 }
  }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 80 }, ["MITRE_T1041", "OWASP_FORM_ACTION"]);

  add(`network-beacon-after-sensitive-${index}`, "observed-network", {
    hasPasswordField: index <= 2,
    hasOTP: index > 2,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 },
    networkSignals: { totalRequests: 1, thirdPartyRequests: 1, thirdPartyXHRRequests: 1, writeRequests: 1, writeRequestsAfterFormSubmit: 1, thirdPartyWriteRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1, beaconOrPingAfterSensitiveInput: 1 }
  }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }, ["MITRE_T1041"]);
}

add("network-http-generic-write", "observed-network", {
  url: "http://example.test/contact", pageProtocol: "http:",
  dataLeakSignals: { formCount: 1 },
  networkSignals: { writeRequests: 1, insecureWriteRequests: 1, writeRequestsAfterFormSubmit: 1, insecureWriteRequestsAfterFormSubmit: 1 }
}, { level: "SUSPICIOUS", min: 35, max: 69 }, ["MITRE_T1048_003"]);
add("network-query-image-after-sensitive-form", "observed-network", {
  dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 },
  networkSignals: { thirdPartyRequests: 1, queryBearingGetAfterSensitiveForm: 1 }
}, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }, ["MITRE_T1041"]);
add("network-http-generic-write-many", "observed-network", {
  url: "http://example.test/upload", pageProtocol: "http:",
  dataLeakSignals: { formCount: 1 },
  networkSignals: { writeRequests: 3, insecureWriteRequests: 3, writeRequestsAfterFormSubmit: 3, insecureWriteRequestsAfterFormSubmit: 3 }
}, { level: "SUSPICIOUS", min: 35, max: 69 }, ["MITRE_T1048_003"]);
add("network-secure-third-party-write-no-sensitive", "observed-network", {
  networkSignals: { thirdPartyRequests: 1, thirdPartyXHRRequests: 1, writeRequests: 1, writeRequestsAfterFormSubmit: 1, thirdPartyWriteRequestsAfterFormSubmit: 1 }
}, { level: "SAFE", max: 34 }, ["BENIGN_CONTROL"]);
add("network-secure-analytics-beacon-no-sensitive", "observed-network", {
  networkSignals: { thirdPartyRequests: 2, thirdPartyXHRRequests: 2, writeRequests: 2 }
}, { level: "SAFE", max: 20 }, ["BENIGN_CONTROL"]);

const scriptCases = [
  ["intent-dynamic-endpoint", { dataLeakSignals: { scriptNetworkSinkCount: 1, dynamicEndpointAssemblyCount: 1, externalUrlHints: ["https://relay.invalid/collect"] } }, { level: "SUSPICIOUS", min: 35, max: 55 }],
  ["intent-delayed-form-relay", { dataLeakSignals: { formCount: 1, credentialLikeTextFieldCount: 1, localFormWithJsSinkIndicator: true, scriptNetworkSinkCount: 1, dynamicEndpointAssemblyCount: 1, delayedRelayIndicator: true, externalUrlHints: ["https://relay.invalid/collect"] } }, { level: "SUSPICIOUS", min: 35, max: 60 }],
  ["intent-popup-relay", { dataLeakSignals: { popupMessageTrapIndicator: true, scriptNetworkSinkCount: 1, externalUrlHints: ["https://relay.invalid/consent"] } }, { level: "SUSPICIOUS", min: 35, max: 60 }],
  ["intent-recovery-relay", { dataLeakSignals: { sensitiveTextareaCount: 1, clipboardReadIndicator: true, scriptNetworkSinkCount: 1, externalUrlHints: ["https://relay.invalid/vault"] } }, { level: "SUSPICIOUS", min: 35, max: 60 }],
  ["intent-sink-only", { dataLeakSignals: { scriptNetworkSinkCount: 1 } }, { level: "SAFE", max: 15 }],
  ["intent-external-url-only", { dataLeakSignals: { externalUrlHints: ["https://cdn.example.invalid/api"] } }, { level: "SAFE", max: 15 }],
  ["intent-delay-only", { dataLeakSignals: { delayedRelayIndicator: true } }, { level: "SAFE", max: 15 }],
  ["intent-popup-only", { dataLeakSignals: { popupMessageTrapIndicator: true } }, { level: "SAFE", max: 15 }]
];
scriptCases.forEach(([id, signals, expect]) => add(id, "script-intent-medium-priority", signals, expect, ["MITRE_T1041", "STATIC_INTENT_ONLY"]));

const corpus = {
  name: "Project Argus Browser Exfiltration Evaluation Corpus",
  version: "3.0.0",
  generatedAt: "2026-07-10",
  privacy: "Synthetic metadata only. No credentials, request bodies, or packet payloads are included.",
  sourceSummary: [
    "MITRE ATT&CK T1041 and T1048.003",
    "OWASP Form Action Hijacking",
    "NIST SP 800-52 Rev. 2",
    "CIC-Bell-DNS-EXF-2021 feature design",
    "CIC-IDS2017, UNSW-NB15, and CTU-13 benign-versus-attack evaluation principles"
  ],
  cases
};

fs.writeFileSync(outputPath, `${JSON.stringify(corpus, null, 2)}\n`, "utf8");
console.log(`Generated ${cases.length} cases at ${outputPath}`);
