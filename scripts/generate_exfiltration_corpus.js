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
      localFormWithJsSinkIndicator: false,
      formValueReadIndicator: false,
      formDataReadIndicator: false,
      sensitiveStorageWriteIndicator: false,
      cookieReadIndicator: false,
      encodedPayloadIndicator: false,
      webSocketSendIndicator: false,
      wildcardPostMessageIndicator: false
    },
    securitySignals: {
      responseHeadersObserved: false,
      hasContentSecurityPolicy: false,
      hasStrictTransportSecurity: false,
      hasXContentTypeOptions: false,
      hasReferrerPolicy: false,
      hasPermissionsPolicy: false,
      missingSecurityHeaderCount: 0,
      mixedContentRequestCount: 0,
      insecureActiveContentRequestCount: 0,
      thirdPartyScriptWithoutIntegrityCount: 0,
      unsandboxedThirdPartyIframeCount: 0
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
    securitySignals: {
      ...base.securitySignals,
      ...(overrides.securitySignals || {})
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
  const targetScore = Number.isFinite(expect.targetScore)
    ? expect.targetScore
    : Number.isFinite(expect.min) && Number.isFinite(expect.max)
      ? Math.round((expect.min + expect.max) / 2)
      : Number.isFinite(expect.min)
        ? Math.min(96, expect.min + 10)
        : Math.round((expect.max || 12) * 0.55);
  cases.push({ id, group, signals: mergeSignals(overrides), expect: { ...expect, targetScore }, sourceTags });
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
  ["context-full-login-flow", { hasPasswordField: true, hasOTP: true, hasLoginKeyword: true }, { level: "SAFE", max: 34 }],
  ["context-bank-language", { hasPasswordField: true, hasOTP: true, foundBankingKeywords: ["bank", "verify account"] }, { level: "HIGH_RISK", category: "FAKE_BANKING", min: 70 }],
  ["context-store-language", { foundStoreKeywords: ["Google Play", "Play Store"] }],
  ["context-store-with-apk", { foundStoreKeywords: ["Play Store"], apkLinks: [{ href: "https://download.example.test/app.apk" }] }, { level: "SUSPICIOUS", min: 35, max: 60 }],
  ["context-risk-domain", { domain: "secure-login-update.example.test", suspiciousDomainSignals: ["Domain contains suspicious word: login."] }],
  ["context-lookalike-domain", { domain: "paypa1-account.example.test" }],
  ["context-clipboard-only", { dataLeakSignals: { clipboardReadIndicator: true } }],
  ["context-file-metadata-only", { dataLeakSignals: { fileMetadataHarvestIndicator: true } }]
];
contextCases.forEach(([id, signals, expect]) => add(id, "context-low-priority", signals, expect || { level: "SAFE", max: 34 }, ["CONTEXT_ONLY"]));

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

// Expanded v4 evaluation families. These cases are synthetic browser-observable
// metadata derived from public threat taxonomies; no page contents or secrets are stored.
for (let index = 1; index <= 10; index += 1) {
  const genericHttpForm = index <= 6 && index % 4 !== 0;
  add(`expanded-benign-trusted-${index}`, "expanded-benign-control", {
    domain: index <= 3 ? "accounts.google.com" : `service${index}.example.test`,
    isTrustedDomain: index <= 3,
    hasPasswordField: index % 3 === 0,
    hasLoginKeyword: index % 2 === 0,
    securitySignals: {
      responseHeadersObserved: true,
      hasContentSecurityPolicy: true,
      hasStrictTransportSecurity: true,
      hasXContentTypeOptions: true,
      hasReferrerPolicy: true,
      hasPermissionsPolicy: index % 2 === 0
    },
    networkSignals: { totalRequests: 8 + index, thirdPartyRequests: index % 4 }
  }, { level: "SAFE", max: 20 }, ["BENIGN_CONTROL", "OWASP_SECURITY_HEADERS"]);

  add(`expanded-benign-form-${index}`, "expanded-benign-control", {
    url: genericHttpForm ? `http://form-${index}.example.test/search` : `https://form-${index}.example.test/submit`,
    domain: `form-${index}.example.test`,
    pageProtocol: genericHttpForm ? "http:" : "https:",
    dataLeakSignals: {
      formCount: 1,
      sensitiveFormCount: index % 4 === 0 ? 1 : 0,
      httpFormActionCount: genericHttpForm ? 1 : 0
    },
    networkSignals: {
      totalRequests: 4,
      writeRequests: 1,
      writeRequestsAfterFormSubmit: 1,
      sensitiveWriteRequestsAfterFormSubmit: index % 4 === 0 ? 1 : 0
    }
  }, { level: "SAFE", max: 34 }, ["BENIGN_CONTROL"]);

  add(`expanded-benign-library-${index}`, "expanded-benign-control", {
    dataLeakSignals: { externalScriptCount: 2 + (index % 3) },
    securitySignals: {
      responseHeadersObserved: true,
      hasContentSecurityPolicy: index % 2 === 0,
      hasXContentTypeOptions: true,
      hasReferrerPolicy: true,
      missingSecurityHeaderCount: index % 2 === 0 ? 1 : 2,
      thirdPartyScriptWithoutIntegrityCount: index % 3
    },
    networkSignals: { totalRequests: 12, thirdPartyRequests: 5, thirdPartyXHRRequests: 1 }
  }, { level: "SAFE", max: 20 }, ["BENIGN_CONTROL", "OWASP_THIRD_PARTY_JS"]);
}

for (let index = 1; index <= 10; index += 1) {
  add(`expanded-phishing-flow-${index}`, "expanded-phishing", {
    domain: index <= 5 ? `secure-account-${index}.example.test` : `paypa1-verify-${index}.example.test`,
    hasPasswordField: true,
    hasOTP: index % 2 === 0,
    hasLoginKeyword: index === 2 ? false : true,
    foundBankingKeywords: index % 2 === 0 ? ["verify bank account"] : [],
    suspiciousDomainSignals: index === 2 ? [] : ["Domain contains account-verification wording.", "Domain contains secure-update wording."],
    dataLeakSignals: { formCount: index === 2 ? 0 : 1, sensitiveFormCount: index === 2 ? 0 : 1 }
  }, index % 2 === 0
    ? { level: "HIGH_RISK", category: "FAKE_BANKING", min: 70 }
    : { level: "SUSPICIOUS", min: 35, max: 60 }, ["PHIUSIIL", "MITRE_T1056_003"]);
}

for (let index = 1; index <= 5; index += 1) {
  add(`expanded-phishing-cross-domain-${index}`, "expanded-phishing", {
    domain: `identity-check-${index}.example.test`,
    hasPasswordField: index % 2 === 1,
    hasOTP: index % 2 === 0,
    hasLoginKeyword: true,
    dataLeakSignals: {
      formCount: 1,
      sensitiveFormCount: 1,
      crossDomainFormActionCount: 1,
      passwordCrossDomainForm: index % 2 === 1,
      otpOrPaymentCrossDomainForm: index % 2 === 0
    }
  }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 75 }, ["CIC_TRAP4PHISH_2025", "OWASP_FORM_ACTION"]);

  add(`expanded-fake-store-${index}`, "expanded-phishing", {
    domain: `play-security-${index}.example.test`,
    foundStoreKeywords: ["Google Play", "Play Store"],
    apkLinks: [{ href: `https://cdn-${index}.example.invalid/security-update.apk` }],
    hasLoginKeyword: true,
    suspiciousDomainSignals: ["Unofficial app-store-style domain."],
    dataLeakSignals: { thirdPartyApkLinks: [`https://cdn-${index}.example.invalid/security-update.apk`] }
  }, { level: "HIGH_RISK", category: "FAKE_APP_STORE", min: 70 }, ["URLHAUS", "CIC_TRAP4PHISH_2025"]);

  add(`expanded-brand-credential-${index}`, "expanded-phishing", {
    domain: `g00gle-login-${index}.example.test`,
    hasPasswordField: true,
    hasOTP: true,
    hasLoginKeyword: true,
    suspiciousDomainSignals: ["Brand-like login domain."],
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, credentialLikeTextFieldCount: 1 }
  }, { level: "SUSPICIOUS", min: 35, max: 60 }, ["PHIUSIIL", "MITRE_T1056_003"]);
}

for (let index = 1; index <= 5; index += 1) {
  const endpoint = `https://relay-${index}.example.invalid/collect`;
  add(`expanded-form-value-relay-${index}`, "expanded-client-exfiltration", {
    hasPasswordField: true,
    dataLeakSignals: {
      formCount: 1,
      sensitiveFormCount: 1,
      formValueReadIndicator: true,
      scriptNetworkSinkCount: 1,
      externalUrlHints: [endpoint],
      localFormWithJsSinkIndicator: true
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["MITRE_T1056_003", "OWASP_CLIENT_SIDE"]);

  add(`expanded-encoded-formdata-relay-${index}`, "expanded-client-exfiltration", {
    hasOTP: true,
    dataLeakSignals: {
      formCount: 1,
      sensitiveFormCount: 1,
      formDataReadIndicator: true,
      encodedPayloadIndicator: true,
      scriptNetworkSinkCount: 1,
      externalUrlHints: [endpoint]
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 40, max: 60 }, ["MITRE_T1027", "MITRE_T1056_003"]);

  add(`expanded-storage-cookie-relay-${index}`, "expanded-client-exfiltration", {
    dataLeakSignals: {
      sensitiveStorageWriteIndicator: true,
      cookieReadIndicator: true,
      scriptNetworkSinkCount: 1,
      externalUrlHints: [endpoint]
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["OWASP_BROWSER_STORAGE", "OWASP_CLIENT_SIDE"]);

  add(`expanded-websocket-sensitive-${index}`, "expanded-client-exfiltration", {
    hasPasswordField: true,
    dataLeakSignals: {
      formCount: 1,
      sensitiveFormCount: 1,
      formValueReadIndicator: true,
      webSocketSendIndicator: true
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["MITRE_T1041", "OWASP_CLIENT_SIDE"]);

  add(`expanded-postmessage-relay-${index}`, "expanded-client-exfiltration", {
    hasOTP: true,
    dataLeakSignals: {
      formCount: 1,
      sensitiveFormCount: 1,
      wildcardPostMessageIndicator: true,
      scriptNetworkSinkCount: 1,
      externalUrlHints: [endpoint],
      sensitiveTextareaCount: index <= 3 ? 1 : 0,
      clipboardReadIndicator: index <= 3
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["OWASP_CLIENT_SIDE"]);

  if (index <= 2) {
    add(`expanded-script-control-${index}`, "expanded-client-exfiltration", {
      dataLeakSignals: {
        formValueReadIndicator: index % 2 === 0,
        encodedPayloadIndicator: index % 2 === 1
      }
    }, { level: "SAFE", max: 20 }, ["BENIGN_CONTROL"]);
  } else {
    add(`expanded-recovery-relay-${index}`, "expanded-client-exfiltration", {
      dataLeakSignals: {
        sensitiveTextareaCount: 1,
        clipboardReadIndicator: true,
        scriptNetworkSinkCount: 1,
        externalUrlHints: [endpoint]
      }
    }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["MITRE_T1056", "OWASP_CLIENT_SIDE"]);
  }
}

for (let index = 1; index <= 5; index += 1) {
  add(`expanded-mixed-sensitive-${index}`, "expanded-browser-protection", {
    hasPasswordField: index % 2 === 1,
    hasOTP: index % 2 === 0,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 },
    securitySignals: {
      responseHeadersObserved: true,
      mixedContentRequestCount: 2,
      insecureActiveContentRequestCount: 1,
      missingSecurityHeaderCount: 3
    }
  }, { level: "HIGH_RISK", category: "INSECURE_FORM_SUBMISSION", min: 70 }, ["CWE_319", "OWASP_SECURITY_HEADERS"]);

  add(`expanded-third-party-credential-page-${index}`, "expanded-browser-protection", {
    hasPasswordField: true,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, externalScriptCount: 3 },
    securitySignals: {
      responseHeadersObserved: true,
      hasXContentTypeOptions: true,
      missingSecurityHeaderCount: 3,
      thirdPartyScriptWithoutIntegrityCount: 3
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["OWASP_THIRD_PARTY_JS", "OWASP_SECURITY_HEADERS"]);

  add(`expanded-missing-headers-only-${index}`, "expanded-browser-protection", {
    securitySignals: { responseHeadersObserved: true, missingSecurityHeaderCount: 5 }
  }, { level: "SAFE", max: 15 }, ["BENIGN_CONTROL", "OWASP_SECURITY_HEADERS"]);

  add(`expanded-no-sri-control-${index}`, "expanded-browser-protection", {
    dataLeakSignals: { externalScriptCount: 4 },
    securitySignals: { responseHeadersObserved: true, missingSecurityHeaderCount: 2, thirdPartyScriptWithoutIntegrityCount: 4 }
  }, { level: "SAFE", max: 20 }, ["BENIGN_CONTROL", "OWASP_THIRD_PARTY_JS"]);

  add(`expanded-iframe-credential-${index}`, "expanded-browser-protection", {
    hasPasswordField: true,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, hiddenIframeCount: 1 },
    securitySignals: {
      responseHeadersObserved: true,
      missingSecurityHeaderCount: 3,
      unsandboxedThirdPartyIframeCount: 1
    }
  }, { level: "SUSPICIOUS", category: "DATA_EXFILTRATION", min: 35, max: 60 }, ["OWASP_CLIENT_SIDE", "OWASP_SECURITY_HEADERS"]);
}

for (let index = 1; index <= 5; index += 1) {
  const apk = `http://download-${index}.example.invalid/update.apk`;
  add(`expanded-http-apk-${index}`, "expanded-download-redirect", {
    url: `http://store-${index}.example.test/`,
    domain: `store-${index}.example.test`,
    pageProtocol: "http:",
    foundStoreKeywords: ["Play Store"],
    apkLinks: [{ href: apk }],
    dataLeakSignals: { thirdPartyApkLinks: [apk], httpApkLinks: [apk] }
  }, { level: "HIGH_RISK", category: "MALICIOUS_APK", min: 70 }, ["URLHAUS", "CWE_319"]);

  add(`expanded-submit-redirect-${index}`, "expanded-download-redirect", {
    hasPasswordField: true,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 },
    networkSignals: {
      totalRequests: 4,
      thirdPartyRequests: 3,
      requestsAfterFormSubmit: 3,
      temporalSignals: { formSubmitThenThirdPartyCount: 3, formSubmitThenCrossDomainRedirectCount: 1 }
    }
  }, { level: "HIGH_RISK", category: "DATA_EXFILTRATION", min: 70 }, ["MITRE_T1041", "CIC_TRAP4PHISH_2025"]);

  add(`expanded-secure-apk-context-${index}`, "expanded-download-redirect", {
    foundStoreKeywords: ["Install App"],
    apkLinks: [{ href: `https://downloads.example.test/app-${index}.apk` }]
  }, { level: "SUSPICIOUS", min: 35, max: 60 }, ["URLHAUS", "STATIC_CONTEXT"]);
}

for (let index = 1; index <= 5; index += 1) {
  add(`expanded-content-gambling-${index}`, "expanded-content-low-priority", {
    domain: `casino-${index}.example.test`,
    foundGamblingKeywords: ["casino", "slot", "bet"],
    domainCategorySignals: { gambling: ["casino"], adult: [] },
    hasAdHeavySignal: true
  }, { level: "SAFE", max: 12 }, ["CONTENT_ONLY"]);

  add(`expanded-content-adult-${index}`, "expanded-content-low-priority", {
    domain: `adult-${index}.example.test`,
    foundAdultKeywords: ["adult", "18+"],
    domainCategorySignals: { gambling: [], adult: ["adult"] },
    hasAdHeavySignal: true
  }, { level: "SAFE", max: 12 }, ["CONTENT_ONLY"]);
}

if (cases.length !== 200) {
  throw new Error(`Expected exactly 200 evaluation cases, generated ${cases.length}.`);
}

const corpus = {
  name: "Project Argus Browser Exfiltration Evaluation Corpus",
  version: "4.0.0",
  generatedAt: "2026-07-10",
  privacy: "Synthetic metadata only. No credentials, request bodies, or packet payloads are included.",
  sourceSummary: [
    "MITRE ATT&CK T1041 and T1048.003",
    "OWASP Form Action Hijacking",
    "NIST SP 800-52 Rev. 2",
    "CIC-Trap4Phish 2025 and UCI PhiUSIIL phishing feature families",
    "URLHaus malicious download URL taxonomy",
    "MITRE ATT&CK T1056 Input Capture and T1027 Obfuscated Files or Information",
    "OWASP Client-Side Security Risks, Browser Storage, Third-Party JavaScript, and Security Headers",
    "CWE-319 Cleartext Transmission of Sensitive Information",
    "CIC-Bell-DNS-EXF-2021 feature design",
    "CIC-IDS2017, UNSW-NB15, and CTU-13 benign-versus-attack evaluation principles"
  ],
  cases
};

fs.writeFileSync(outputPath, `${JSON.stringify(corpus, null, 2)}\n`, "utf8");
console.log(`Generated ${cases.length} cases at ${outputPath}`);
