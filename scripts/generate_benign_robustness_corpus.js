"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const core = JSON.parse(fs.readFileSync(path.join(root, "datasets", "exfiltration_eval_cases.json"), "utf8"));
const outputPath = path.join(root, "datasets", "benign_robustness_cases.json");
const phiusiil = JSON.parse(fs.readFileSync(path.join(root, "datasets", "phiusiil_benign_cases.json"), "utf8"));
const template = core.cases.find((testCase) => testCase.id === "safe-static-https").signals;

function mergeSignals(overrides = {}) {
  const base = JSON.parse(JSON.stringify(template));
  return {
    ...base,
    ...overrides,
    domainCategorySignals: { ...base.domainCategorySignals, ...(overrides.domainCategorySignals || {}) },
    dataLeakSignals: { ...base.dataLeakSignals, ...(overrides.dataLeakSignals || {}) },
    securitySignals: { ...base.securitySignals, ...(overrides.securitySignals || {}) },
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
function add(id, group, signals, sourceTags) {
  cases.push({
    id,
    group,
    signals: mergeSignals(signals),
    expect: { level: "SAFE", max: 34, targetScore: 8 },
    sourceTags
  });
}

const trustedDomains = [
  "accounts.google.com", "github.com", "microsoft.com", "apple.com", "youtube.com",
  "roblox.com", "finance.yahoo.com", "linkedin.com", "reddit.com", "discord.com",
  "steamcommunity.com", "epicgames.com", "kbank.co.th", "scb.co.th", "bangkokbank.com",
  "set.or.th", "sec.or.th", "bot.or.th", "f-droid.org", "wikipedia.org"
];

for (let index = 1; index <= 10; index += 1) {
  const domain = trustedDomains[index - 1];
  add(`benign-trusted-platform-${index}`, "trusted-platform", {
    url: `https://${domain}/account`, domain, pathname: "/account", isTrustedDomain: true,
    hasPasswordField: index % 2 === 0, hasOTP: index % 3 === 0, hasLoginKeyword: true,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: index % 2 === 0 ? 1 : 0 },
    securitySignals: secureHeaders(),
    networkSignals: { totalRequests: 18, thirdPartyRequests: 4, writeRequests: 1, writeRequestsAfterFormSubmit: 1 }
  }, ["TRANCO_CONTROL", "TRUSTED_PLATFORM"]);

  const loginDomain = index % 4 === 0 ? `login-${index}.company.example` : `portal${index}.community.example`;
  add(`benign-independent-auth-${index}`, "independent-secure-auth", {
    url: `https://${loginDomain}/signin`, domain: loginDomain, pathname: "/signin",
    hasPasswordField: true, hasOTP: index % 2 === 0, hasLoginKeyword: true,
    suspiciousDomainSignals: index % 4 === 0 ? ["Domain contains generic login wording."] : [],
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1 },
    securitySignals: secureHeaders(),
    networkSignals: { totalRequests: 9, writeRequests: 1, writeRequestsAfterFormSubmit: 1, sensitiveWriteRequestsAfterFormSubmit: 1 }
  }, ["PHIUSIIL_LEGITIMATE", "BENIGN_AUTH_CONTROL"]);

  add(`benign-enterprise-sso-${index}`, "enterprise-sso", {
    url: `https://sso${index}.enterprise.example/auth`, domain: `sso${index}.enterprise.example`, pathname: "/auth",
    hasPasswordField: index % 2 === 1, hasOTP: true, hasLoginKeyword: true,
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, externalScriptCount: 2 },
    securitySignals: { ...secureHeaders(), thirdPartyScriptWithoutIntegrityCount: 0 },
    networkSignals: { totalRequests: 14, thirdPartyRequests: 3, thirdPartyXHRRequests: 1, writeRequests: 1 }
  }, ["CIC_TRAP4PHISH_BENIGN", "BENIGN_SSO_CONTROL"]);

  add(`benign-commerce-payment-${index}`, "secure-commerce", {
    url: `https://shop${index}.merchant.example/checkout`, domain: `shop${index}.merchant.example`, pathname: "/checkout",
    hasPasswordField: index % 5 === 0, hasOTP: index % 7 === 0, hasLoginKeyword: false,
    foundBankingKeywords: index % 4 === 0 ? ["payment"] : [],
    dataLeakSignals: { formCount: 1, sensitiveFormCount: 1, externalScriptCount: 3, thirdPartyIframeCount: 1 },
    securitySignals: secureHeaders(),
    networkSignals: { totalRequests: 24, thirdPartyRequests: 8, thirdPartyXHRRequests: 2, writeRequests: 1, writeRequestsAfterFormSubmit: 1 }
  }, ["BENIGN_COMMERCE_CONTROL"]);

  add(`benign-generic-http-${index}`, "generic-http", {
    url: `http://archive${index}.example.test/search`, domain: `archive${index}.example.test`, pathname: "/search", pageProtocol: "http:",
    dataLeakSignals: { formCount: 1, httpFormActionCount: 1 },
    securitySignals: { responseHeadersObserved: true, missingSecurityHeaderCount: 5 },
    networkSignals: { totalRequests: 6, insecureHttpRequests: 6, writeRequests: 1, insecureWriteRequests: 1 }
  }, ["BENIGN_HTTP_CONTROL"]);

  const gambling = index % 2 === 0;
  add(`benign-content-media-${index}`, "content-media", {
    domain: `${gambling ? "sports" : "adult"}${index}.media.example`,
    foundGamblingKeywords: gambling ? ["casino", "bet"] : [],
    foundAdultKeywords: gambling ? [] : ["adult", "18+"],
    domainCategorySignals: { gambling: gambling ? ["bet"] : [], adult: gambling ? [] : ["adult"] },
    hasAdHeavySignal: true
  }, ["CONTENT_ONLY_CONTROL"]);

  const trustedDownload = index <= 10;
  const downloadDomain = index % 2 === 0 ? "f-droid.org" : "github.com";
  add(`benign-developer-download-${index}`, "developer-download", trustedDownload ? {
    url: `https://${downloadDomain}/projects/app`, domain: downloadDomain, pathname: "/projects/app", isTrustedDomain: true,
    apkLinks: [{ href: `https://${downloadDomain}/releases/app-${index}.apk` }],
    foundStoreKeywords: ["Install App"]
  } : {
    domain: `docs${index}.developer.example`, foundStoreKeywords: ["Install App", "download app"], apkLinks: []
  }, ["TRANCO_CONTROL", "LEGITIMATE_DOWNLOAD_CONTROL"]);

  const scriptMode = index % 7;
  add(`benign-script-storage-${index}`, "script-storage", {
    domain: `app${index}.productivity.example`,
    dataLeakSignals: {
      formValueReadIndicator: scriptMode === 0,
      formDataReadIndicator: scriptMode === 1,
      sensitiveStorageWriteIndicator: scriptMode === 2,
      cookieReadIndicator: scriptMode === 3,
      encodedPayloadIndicator: scriptMode === 4,
      webSocketSendIndicator: scriptMode === 5,
      wildcardPostMessageIndicator: scriptMode === 6,
      scriptNetworkSinkCount: scriptMode === 4 ? 1 : 0
    },
    securitySignals: secureHeaders()
  }, ["BENIGN_SCRIPT_CONTROL", "OWASP_CLIENT_SIDE"]);

  add(`benign-network-analytics-${index}`, "network-analytics", {
    domain: `news${index}.publisher.example`,
    networkSignals: {
      totalRequests: 30 + index, thirdPartyRequests: 12, thirdPartyScriptRequests: 4,
      thirdPartyXHRRequests: 3, writeRequests: 2, thirdPartyWriteRequests: 2
    },
    securitySignals: secureHeaders()
  }, ["BENIGN_NETWORK_CONTROL"]);

  add(`benign-browser-posture-${index}`, "browser-posture", {
    domain: `legacy${index}.organization.example`,
    dataLeakSignals: { externalScriptCount: 4, thirdPartyIframeCount: 2 },
    securitySignals: {
      responseHeadersObserved: true, missingSecurityHeaderCount: 5,
      mixedContentRequestCount: index % 2, insecureActiveContentRequestCount: 0,
      thirdPartyScriptWithoutIntegrityCount: 4, unsandboxedThirdPartyIframeCount: 2
    }
  }, ["BENIGN_POSTURE_CONTROL", "OWASP_SECURITY_HEADERS"]);
}

for (const testCase of phiusiil.cases) {
  cases.push(testCase);
}

if (cases.length !== 200 || new Set(cases.map((testCase) => testCase.id)).size !== 200) {
  throw new Error(`Expected 200 unique benign cases, generated ${cases.length}.`);
}

const corpus = {
  name: "Project Argus Benign Website Robustness Corpus",
  version: "1.0.0",
  generatedAt: "2026-07-10",
  privacy: "Synthetic browser metadata only. No page content, credentials, payloads, cookies, or browsing history.",
  sourceSummary: [
    "UCI PhiUSIIL legitimate URL class",
    "CIC-Trap4Phish benign HTML class",
    "Tranco research-oriented popular-site controls",
    "OWASP client-side and security-header benign counterexamples"
  ],
  cases
};

fs.writeFileSync(outputPath, `${JSON.stringify(corpus, null, 2)}\n`, "utf8");
console.log(`Generated ${cases.length} benign robustness cases at ${outputPath}`);

function secureHeaders() {
  return {
    responseHeadersObserved: true,
    hasContentSecurityPolicy: true,
    hasStrictTransportSecurity: true,
    hasXContentTypeOptions: true,
    hasReferrerPolicy: true,
    hasPermissionsPolicy: true,
    missingSecurityHeaderCount: 0,
    thirdPartyScriptWithoutIntegrityCount: 0,
    unsandboxedThirdPartyIframeCount: 0
  };
}
