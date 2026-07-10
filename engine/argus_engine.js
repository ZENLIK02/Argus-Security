(function exposeArgusEngine(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.ArgusEngine = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createArgusEngine() {
  "use strict";

  const DEFAULT_POLICY = {
    version: "3.0.0",
    thresholds: {
      suspicious: 35,
      highRisk: 70,
      maximumContentOnlyScore: 12,
      maximumContextOnlyScore: 60,
      trustedDomainCap: 20
    },
    combiner: {
      sameCategoryDecay: [1, 0.8, 0.55, 0.4],
      secondaryCategoryFactor: 0.25,
      tertiaryCategoryFactor: 0.1,
      maximumReasons: 8
    }
  };

  let activePolicy = DEFAULT_POLICY;

  function evaluate(rawSignals, categoryConfig, rawPolicy) {
    const signals = rawSignals || {};
    const policy = mergePolicy(rawPolicy);
    activePolicy = policy;
    const analyzerOutputs = [
      analyzeDomain(signals),
      analyzeCredentials(signals),
      analyzeForms(signals),
      analyzeScripts(signals),
      analyzeDownloads(signals),
      analyzeContent(signals),
      analyzeNetwork(signals)
    ];
    const evidence = analyzerOutputs.flatMap((output) => output.evidence);
    evidence.push(...analyzeCombinations(signals, evidence));

    const decisionTier = getDecisionTier(evidence);
    const strongEvidence = evidence.some((item) => item.priority === 1 && item.decisive && item.confidence >= 0.8);
    if (signals.isSearchEnginePage && !strongEvidence) {
      return finalizeEarlySafe("Official search engine result page without concrete danger signals.", analyzerOutputs, policy, 0.97);
    }

    if (isOfficialAppStore(signals.domain) && !strongEvidence && toArray(signals.apkLinks).length === 0) {
      return finalizeEarlySafe("Official app store domain without direct APK or credential exfiltration evidence.", analyzerOutputs, policy, 0.97);
    }

    const categoryScores = combineByCategory(evidence, policy);
    let category = chooseCategory(categoryScores, signals);
    let score = combineCategoryScores(categoryScores, category, policy);
    score = applyScoreFloors(score, evidence, policy);

    if (decisionTier === "CONTENT_CATEGORY") {
      score = Math.min(score, policy.thresholds.maximumContentOnlyScore);
    }

    if (decisionTier === "CONTEXT_OR_INTENT") {
      score = Math.min(score, policy.thresholds.maximumContextOnlyScore);
    }

    if (signals.isTrustedDomain && !strongEvidence) {
      score = Math.min(score, policy.thresholds.trustedDomainCap);
      category = "SAFE";
    }

    if (isFinanceOrNewsSafeContext(signals) && !strongEvidence) {
      score = Math.min(score, policy.thresholds.trustedDomainCap);
      category = "SAFE";
    }

    const level = levelFromScore(score, policy);
    if (level === "SAFE") {
      category = "SAFE";
    }
    const confidence = calculateConfidence(evidence, signals, level);
    const reasons = selectReasons(evidence, policy);
    const configuredIds = new Set(toArray(categoryConfig && categoryConfig.categories).map((item) => item.id));
    if (category !== "SAFE" && configuredIds.size > 0 && !configuredIds.has(category)) {
      reasons.push(`Category ${category} is defined by the local decision engine.`);
    }

    return {
      score: clampScore(score),
      riskScore: clampScore(score),
      level,
      category: category || "SAFE",
      confidence,
      decisionTier,
      reasons: reasons.length ? reasons : ["No high-risk indicators were detected."],
      evidence: evidence.map(publicEvidence),
      toolResults: buildToolResults(analyzerOutputs, evidence),
      policyVersion: policy.version,
      shouldWarn: false,
      source: "LOCAL_MODEL"
    };
  }

  function analyzeDomain(signals) {
    const evidence = [];
    const domain = String(signals.domain || "").toLowerCase();
    if (signals.isTrustedDomain) {
      return tool("DOMAIN_ANALYZER", evidence);
    }
    if (domain.length > 35) {
      evidence.push(finding("DOMAIN_LONG", "DOMAIN_ANALYZER", "BRAND_IMPERSONATION", 6, 0.55, "low", "Domain is unusually long."));
    }
    if ((domain.match(/-/g) || []).length >= 2) {
      evidence.push(finding("DOMAIN_HYPHENS", "DOMAIN_ANALYZER", "BRAND_IMPERSONATION", 8, 0.6, "low", "Domain contains multiple hyphens."));
    }
    if (/^xn--/i.test(domain) || domain.includes(".xn--")) {
      evidence.push(finding("DOMAIN_PUNYCODE", "DOMAIN_ANALYZER", "BRAND_IMPERSONATION", 18, 0.75, "medium", "Domain uses internationalized punycode that can imitate familiar characters."));
    }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      evidence.push(finding("DOMAIN_IP_HOST", "DOMAIN_ANALYZER", "BRAND_IMPERSONATION", 15, 0.72, "medium", "Page uses a raw IP address instead of a normal domain name."));
    }
    if (toArray(signals.suspiciousDomainSignals).length > 0) {
      evidence.push(finding("DOMAIN_RISK_WORDS", "DOMAIN_ANALYZER", "BRAND_IMPERSONATION", 8, 0.55, "low", toArray(signals.suspiciousDomainSignals)[0]));
    }
    if (hasBrandImpersonationPattern(domain)) {
      evidence.push(finding("DOMAIN_BRAND_LOOKALIKE", "DOMAIN_ANALYZER", "BRAND_IMPERSONATION", 34, 0.9, "high", "Domain resembles a known brand impersonation pattern."));
    }
    return tool("DOMAIN_ANALYZER", evidence);
  }

  function analyzeCredentials(signals) {
    const evidence = [];
    const dataLeak = dataLeakOf(signals);
    if (!signals.isTrustedDomain && signals.hasPasswordField) {
      evidence.push(finding("PASSWORD_UNKNOWN_DOMAIN", "CREDENTIAL_ANALYZER", "PHISHING_LOGIN", 18, 0.65, "medium", "Password field found on an untrusted domain."));
    }
    if (!signals.isTrustedDomain && signals.hasOTP) {
      evidence.push(finding("OTP_UNKNOWN_DOMAIN", "CREDENTIAL_ANALYZER", "PHISHING_LOGIN", 22, 0.72, "medium", "OTP or verification-code field found on an untrusted domain."));
    }
    if (!signals.isTrustedDomain && signals.hasLoginKeyword) {
      evidence.push(finding("LOGIN_LANGUAGE", "CREDENTIAL_ANALYZER", "PHISHING_LOGIN", 8, 0.5, "low", "Login or account-verification language found on an untrusted domain."));
    }
    if (!signals.isTrustedDomain && dataLeak.credentialLikeTextFieldCount > 0) {
      evidence.push(finding("DISGUISED_CREDENTIAL_FIELD", "CREDENTIAL_ANALYZER", "PHISHING_LOGIN", 20, 0.78, "medium", `Credential-like text fields detected (${dataLeak.credentialLikeTextFieldCount}).`));
    }
    if (!signals.isTrustedDomain && toArray(signals.foundBankingKeywords).length > 0 && signals.hasPasswordField) {
      evidence.push(finding("BANK_PASSWORD_COMBO", "CREDENTIAL_ANALYZER", "FAKE_BANKING", 30, 0.82, "high", "Banking language appears with a password field on an untrusted domain."));
    }
    if (!signals.isTrustedDomain && toArray(signals.foundBankingKeywords).length > 0 && signals.hasOTP) {
      evidence.push(finding("BANK_OTP_COMBO", "CREDENTIAL_ANALYZER", "FAKE_BANKING", 32, 0.86, "high", "Banking language appears with OTP verification on an untrusted domain."));
    }
    return tool("CREDENTIAL_ANALYZER", evidence);
  }

  function analyzeForms(signals) {
    const evidence = [];
    const dataLeak = dataLeakOf(signals);
    if (dataLeak.crossDomainFormActionCount > 0) {
      evidence.push(finding("CROSS_DOMAIN_FORM", "FORM_ANALYZER", "DATA_EXFILTRATION", 18, 0.7, "medium", "A form submits to a different domain."));
    }
    if (dataLeak.passwordCrossDomainForm) {
      evidence.push(finding("PASSWORD_CROSS_DOMAIN", "FORM_ANALYZER", "DATA_EXFILTRATION", 68, 0.96, "critical", "Password form submits to a different domain.", true));
    }
    if (dataLeak.otpOrPaymentCrossDomainForm) {
      evidence.push(finding("SENSITIVE_CROSS_DOMAIN", "FORM_ANALYZER", "DATA_EXFILTRATION", 72, 0.97, "critical", "OTP, payment, or bank-like fields submit to a different domain.", true));
    }
    if (dataLeak.sensitiveFormCount > 0 && dataLeak.crossDomainFormActionCount > 0 &&
      !dataLeak.passwordCrossDomainForm && !dataLeak.otpOrPaymentCrossDomainForm) {
      evidence.push(finding("SENSITIVE_GENERIC_CROSS_DOMAIN", "FORM_ANALYZER", "DATA_EXFILTRATION", 78, 0.95, "critical", "A sensitive or credential-like form submits to a different domain.", true));
    }
    if (dataLeak.httpFormActionCount > 0) {
      evidence.push(finding("HTTP_FORM", "FORM_ANALYZER", "INSECURE_FORM_SUBMISSION", 38, 0.9, "high", "A form submits information over insecure HTTP."));
    }
    if (dataLeak.passwordHttpForm || dataLeak.otpOrPaymentHttpForm) {
      evidence.push(finding("SENSITIVE_HTTP_FORM", "FORM_ANALYZER", "INSECURE_FORM_SUBMISSION", 76, 0.99, "critical", "Password, OTP, or payment data may be submitted over insecure HTTP.", true));
    }
    if ((dataLeak.sameOriginSensitiveHttpForm || dataLeak.httpPageWithSensitiveForm) &&
      !dataLeak.passwordHttpForm && !dataLeak.otpOrPaymentHttpForm) {
      evidence.push(finding("SENSITIVE_HTTP_PAGE_FORM", "FORM_ANALYZER", "INSECURE_FORM_SUBMISSION", 82, 0.98, "critical", "A sensitive or credential-like form can submit over unencrypted HTTP.", true));
    }
    if (dataLeak.hiddenIframeCount > 0 && (signals.hasPasswordField || signals.hasOTP)) {
      evidence.push(finding("HIDDEN_FRAME_WITH_CREDENTIALS", "FORM_ANALYZER", "DATA_EXFILTRATION", 25, 0.78, "high", "Hidden iframe appears on a page collecting credentials."));
    }
    return tool("FORM_ANALYZER", evidence);
  }

  function analyzeScripts(signals) {
    const evidence = [];
    const dataLeak = dataLeakOf(signals);
    if (!signals.isTrustedDomain && dataLeak.externalScriptCount > 0 && (signals.hasPasswordField || signals.hasOTP)) {
      evidence.push(finding("EXTERNAL_SCRIPT_CREDENTIAL_PAGE", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 12, 0.55, "low", "External scripts run on a page that collects credentials."));
    }
    if (dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.localFormWithJsSinkIndicator) {
      evidence.push(finding("DISGUISED_FORM_JS_SINK", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 40, 0.9, "high", "A local-looking credential form is handled by JavaScript network logic.", true));
    }
    if (dataLeak.scriptNetworkSinkCount > 0 && toArray(dataLeak.externalUrlHints).length > 0) {
      evidence.push(finding("SCRIPT_NETWORK_EXTERNAL_HINT", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 24, 0.78, "medium", "Page script combines network-send behavior with external endpoint hints."));
    }
    if (dataLeak.dynamicEndpointAssemblyCount > 0 && dataLeak.scriptNetworkSinkCount > 0) {
      evidence.push(finding("DYNAMIC_ENDPOINT", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 26, 0.84, "high", "JavaScript assembles a network endpoint dynamically before sending data."));
    }
    if (dataLeak.delayedRelayIndicator && dataLeak.localFormWithJsSinkIndicator) {
      evidence.push(finding("DELAYED_RELAY", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 22, 0.8, "medium", "Form handling includes delayed JavaScript relay behavior."));
    }
    if (dataLeak.popupMessageTrapIndicator && dataLeak.scriptNetworkSinkCount > 0) {
      evidence.push(finding("POPUP_MESSAGE_RELAY", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 38, 0.9, "high", "A popup or consent flow can relay messages into network-send logic.", true));
    }
    if (dataLeak.clipboardReadIndicator) {
      evidence.push(finding("CLIPBOARD_ACCESS", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 22, 0.78, "medium", "Page script requests clipboard access."));
    }
    if (dataLeak.fileMetadataHarvestIndicator) {
      evidence.push(finding("FILE_METADATA_ACCESS", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 20, 0.72, "medium", "Page script inspects uploaded-file metadata."));
    }
    if (dataLeak.sensitiveTextareaCount > 0 && (dataLeak.clipboardReadIndicator || dataLeak.scriptNetworkSinkCount > 0)) {
      evidence.push(finding("RECOVERY_TEXT_DATA_MOVEMENT", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 38, 0.9, "high", "Sensitive recovery-style text appears with script-based data movement.", true));
    }
    if (dataLeak.guardedNetworkToggleIndicator && dataLeak.scriptNetworkSinkCount > 0) {
      evidence.push(finding("GUARDED_NETWORK_SEND", "SCRIPT_INTENT_ANALYZER", "DATA_EXFILTRATION", 12, 0.7, "medium", "Network-send behavior is hidden behind a runtime guard."));
    }
    return tool("SCRIPT_INTENT_ANALYZER", evidence);
  }

  function analyzeDownloads(signals) {
    const evidence = [];
    const dataLeak = dataLeakOf(signals);
    const apkCount = toArray(signals.apkLinks).length;
    if (apkCount > 0) {
      evidence.push(finding("APK_HREF", "DOWNLOAD_ANALYZER", "MALICIOUS_APK", 30, 0.9, "high", `Actual .apk download href detected (${apkCount}).`));
    }
    if (!signals.isTrustedDomain && toArray(signals.foundStoreKeywords).length > 0) {
      evidence.push(finding("STORE_LANGUAGE_UNKNOWN_DOMAIN", "DOWNLOAD_ANALYZER", "FAKE_APP_STORE", 20, 0.68, "medium", "App-store language appears on an unofficial domain."));
    }
    if (toArray(dataLeak.thirdPartyApkLinks).length > 0) {
      evidence.push(finding("THIRD_PARTY_APK", "DOWNLOAD_ANALYZER", "MALICIOUS_APK", 32, 0.92, "high", "APK download is served from an unrelated domain.", true));
    }
    if (toArray(dataLeak.httpApkLinks).length > 0) {
      evidence.push(finding("HTTP_APK", "DOWNLOAD_ANALYZER", "MALICIOUS_APK", 48, 0.98, "critical", "APK download is served over insecure HTTP.", true));
    }
    return tool("DOWNLOAD_ANALYZER", evidence);
  }

  function analyzeContent(signals) {
    const evidence = [];
    if (!signals.isTrustedDomain && (toArray(signals.foundGamblingKeywords).length > 0 || toArray(signals.domainCategorySignals && signals.domainCategorySignals.gambling).length > 0)) {
      evidence.push(finding("GAMBLING_CONTENT", "CONTENT_ANALYZER", "GAMBLING", 35, 0.86, "medium", "Gambling content or a gambling-style domain pattern was detected."));
    }
    if (!signals.isTrustedDomain && (toArray(signals.foundAdultKeywords).length > 0 || toArray(signals.domainCategorySignals && signals.domainCategorySignals.adult).length > 0)) {
      evidence.push(finding("ADULT_CONTENT", "CONTENT_ANALYZER", "ADULT_CONTENT", 35, 0.84, "medium", "Adult content or an adult-content domain pattern was detected."));
    }
    addKeywordFinding(evidence, signals, "foundInvestmentKeywords", "INVESTMENT_SCAM", 26, "Investment or crypto scam language detected.");
    addKeywordFinding(evidence, signals, "foundTechSupportKeywords", "TECH_SUPPORT_SCAM", 26, "Tech-support scam language detected.");
    addKeywordFinding(evidence, signals, "foundFakeShoppingKeywords", "FAKE_SHOPPING", 18, "Suspicious shopping language detected.");
    addKeywordFinding(evidence, signals, "foundPrizeKeywords", "PRIZE_SCAM", 18, "Prize or giveaway scam language detected.");
    addKeywordFinding(evidence, signals, "foundPiratedKeywords", "PIRATED_SOFTWARE", 24, "Pirated software language detected.");
    if (!signals.isTrustedDomain && (signals.hasAdHeavySignal || toArray(signals.foundPopupAbuseKeywords).length > 0)) {
      const id = signals.hasAdHeavySignal ? "AGGRESSIVE_AD_LAYOUT" : "POPUP_ABUSE_LANGUAGE";
      evidence.push(finding(id, "CONTENT_ANALYZER", "MALVERTISING", signals.hasAdHeavySignal ? 45 : 24, 0.78, "medium", "Aggressive advertising or popup-abuse behavior detected."));
    }
    return tool("CONTENT_ANALYZER", evidence);
  }

  function analyzeNetwork(signals) {
    const evidence = [];
    const network = networkOf(signals);
    const temporal = temporalOf(signals);
    if (network.insecureSensitiveWriteRequests > 0) {
      evidence.push(finding("UNENCRYPTED_SENSITIVE_WRITE", "NETWORK_ANALYZER", "INSECURE_FORM_SUBMISSION", 100, 0.99, "critical", "A sensitive form was followed by an unencrypted HTTP write request.", true));
    }
    if (network.crossDomainSensitiveWriteRequests > 0) {
      evidence.push(finding("CROSS_DOMAIN_SENSITIVE_WRITE", "NETWORK_ANALYZER", "DATA_EXFILTRATION", 95, 0.98, "critical", "A sensitive form was followed by a write request to another domain.", true));
    }
    if (network.beaconOrPingAfterSensitiveInput > 0) {
      evidence.push(finding("BEACON_AFTER_SENSITIVE_INPUT", "NETWORK_ANALYZER", "DATA_EXFILTRATION", 88, 0.96, "critical", "A beacon or ping request occurred after sensitive input interaction.", true));
    }
    if (network.queryBearingGetAfterSensitiveForm > 0) {
      evidence.push(finding("QUERY_GET_AFTER_SENSITIVE_FORM", "NETWORK_ANALYZER", "DATA_EXFILTRATION", 84, 0.94, "critical", "A query-bearing image request went to another domain after a sensitive form submission.", true));
    }
    if (network.insecureWriteRequestsAfterFormSubmit > 0 && network.insecureSensitiveWriteRequests === 0) {
      evidence.push(finding("UNENCRYPTED_FORM_WRITE", "NETWORK_ANALYZER", "INSECURE_FORM_SUBMISSION", 45, 0.88, "high", "A form submission was followed by an unencrypted HTTP write request.", true));
    }
    if (network.thirdPartyWriteRequestsAfterFormSubmit > 0 && network.crossDomainSensitiveWriteRequests === 0) {
      evidence.push(finding("THIRD_PARTY_FORM_WRITE", "NETWORK_ANALYZER", "DATA_EXFILTRATION", 12, 0.72, "medium", "A form submission was followed by a write request to another domain."));
    }
    if (network.thirdPartyXHRRequests >= 3 && network.requestsAfterFormSubmit >= 3) {
      evidence.push(finding("POST_SUBMIT_THIRD_PARTY", "NETWORK_ANALYZER", "DATA_EXFILTRATION", 34, 0.88, "high", "Multiple third-party requests occurred shortly after a form submission.", true));
    }
    if (network.requestsAfterPasswordFocus >= 3) {
      evidence.push(finding("POST_PASSWORD_THIRD_PARTY", "NETWORK_ANALYZER", "DATA_EXFILTRATION", 32, 0.86, "high", "Multiple third-party requests occurred after password-field interaction.", true));
    }
    if (temporal.formSubmitThenCrossDomainRedirectCount > 0) {
      evidence.push(finding("POST_SUBMIT_REDIRECT", "NETWORK_ANALYZER", "REDIRECT_SCAM", 46, 0.94, "critical", "Page redirected to another domain soon after form submission.", true));
    }
    if (temporal.downloadAfterFormSubmitCount > 0) {
      evidence.push(finding("POST_SUBMIT_DOWNLOAD", "NETWORK_ANALYZER", "SUSPICIOUS_DOWNLOAD", 32, 0.86, "high", "A download was triggered shortly after form submission.", true));
    }
    if (network.insecureHttpRequests >= 5 && network.thirdPartyRequests >= 3) {
      evidence.push(finding("MANY_INSECURE_REQUESTS", "NETWORK_ANALYZER", "MALVERTISING", 18, 0.7, "medium", "Page made many insecure third-party requests."));
    }
    return tool("NETWORK_ANALYZER", evidence);
  }

  function analyzeCombinations(signals) {
    const evidence = [];
    const dataLeak = dataLeakOf(signals);
    const network = networkOf(signals);
    const temporal = temporalOf(signals);
    if (!signals.isTrustedDomain && signals.hasPasswordField && signals.hasOTP && signals.hasLoginKeyword) {
      evidence.push(finding("FULL_CREDENTIAL_FLOW", "DECISION_COMBINER", "PHISHING_LOGIN", 28, 0.92, "high", "Password, OTP, and account-verification signals appear together.", true));
    }
    if (!signals.isTrustedDomain && toArray(signals.foundStoreKeywords).length > 0 && toArray(signals.apkLinks).length > 0) {
      evidence.push(finding("FAKE_STORE_APK_COMBO", "DECISION_COMBINER", "FAKE_APP_STORE", 52, 0.97, "critical", "Unofficial app-store language appears together with a direct APK download.", true));
    }
    if (!signals.isTrustedDomain && toArray(signals.foundBankingKeywords).length > 0 && signals.hasPasswordField && signals.hasOTP) {
      evidence.push(finding("FAKE_BANK_FULL_FLOW", "DECISION_COMBINER", "FAKE_BANKING", 42, 0.96, "critical", "Banking language, password collection, and OTP verification appear together.", true));
    }
    if (dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.scriptNetworkSinkCount > 0 && dataLeak.dynamicEndpointAssemblyCount > 0) {
      evidence.push(finding("EVASIVE_CREDENTIAL_RELAY", "DECISION_COMBINER", "DATA_EXFILTRATION", 40, 0.95, "critical", "Disguised credential fields connect to dynamically assembled network-send logic.", true));
    }
    if (dataLeak.sensitiveTextareaCount > 0 && dataLeak.clipboardReadIndicator && dataLeak.scriptNetworkSinkCount > 0) {
      evidence.push(finding("RECOVERY_SECRET_RELAY", "DECISION_COMBINER", "DATA_EXFILTRATION", 38, 0.95, "critical", "Recovery-style secret input, clipboard access, and network-send logic appear together.", true));
    }
    if (dataLeak.popupMessageTrapIndicator && dataLeak.scriptNetworkSinkCount > 0 && toArray(dataLeak.externalUrlHints).length > 0) {
      evidence.push(finding("POPUP_EXTERNAL_RELAY", "DECISION_COMBINER", "DATA_EXFILTRATION", 34, 0.94, "critical", "Popup messages can flow into script logic that references an external endpoint.", true));
    }
    if (dataLeak.scriptNetworkSinkCount > 0 && dataLeak.dynamicEndpointAssemblyCount > 0 && toArray(dataLeak.externalUrlHints).length > 0) {
      evidence.push(finding("STATIC_EXFIL_INTENT", "DECISION_COMBINER", "DATA_EXFILTRATION", 10, 0.9, "medium", "Static script analysis found an assembled external endpoint connected to network-send logic."));
    }
    if (network.insecureSensitiveWriteRequests > 0 && network.crossDomainSensitiveWriteRequests > 0) {
      evidence.push(finding("OBSERVED_UNPROTECTED_EXFILTRATION", "DECISION_COMBINER", "DATA_EXFILTRATION", 100, 0.99, "critical", "Sensitive interaction was followed by an unencrypted write to another domain.", true));
    }
    if (temporal.formSubmitThenThirdPartyCount >= 3 && temporal.formSubmitThenCrossDomainRedirectCount > 0) {
      evidence.push(finding("EXFILTRATION_SEQUENCE", "DECISION_COMBINER", "DATA_EXFILTRATION", 48, 0.97, "critical", "Form submission was followed by third-party requests and a cross-domain redirect.", true));
    }
    return evidence;
  }

  function combineByCategory(evidence, policy) {
    const grouped = {};
    evidence.forEach((item) => {
      if (!grouped[item.category]) {
        grouped[item.category] = [];
      }
      grouped[item.category].push(item);
    });
    return Object.fromEntries(Object.entries(grouped).map(([category, items]) => {
      const sorted = items.slice().sort((a, b) => effectivePoints(b) - effectivePoints(a));
      const decays = policy.combiner.sameCategoryDecay;
      const score = sorted.reduce((total, item, index) => {
        const decay = decays[Math.min(index, decays.length - 1)] ?? 0.35;
        return total + effectivePoints(item) * decay;
      }, 0);
      return [category, Math.min(100, score)];
    }));
  }

  function combineCategoryScores(categoryScores, dominant, policy) {
    const sorted = Object.entries(categoryScores).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0) {
      return 0;
    }
    const dominantScore = categoryScores[dominant] ?? sorted[0][1];
    const others = sorted.filter(([category]) => category !== dominant);
    return dominantScore + (others[0]?.[1] || 0) * policy.combiner.secondaryCategoryFactor +
      others.slice(1).reduce((total, entry) => total + entry[1] * policy.combiner.tertiaryCategoryFactor, 0);
  }

  function chooseCategory(categoryScores, signals) {
    const dataLeak = dataLeakOf(signals);
    const network = networkOf(signals);
    const temporal = temporalOf(signals);
    if (network.insecureSensitiveWriteRequests > 0 || dataLeak.passwordHttpForm || dataLeak.otpOrPaymentHttpForm ||
      dataLeak.sameOriginSensitiveHttpForm || dataLeak.httpPageWithSensitiveForm) return "INSECURE_FORM_SUBMISSION";
    if (dataLeak.passwordCrossDomainForm || dataLeak.otpOrPaymentCrossDomainForm ||
      (dataLeak.sensitiveFormCount > 0 && dataLeak.crossDomainFormActionCount > 0) ||
      network.crossDomainSensitiveWriteRequests > 0 || network.beaconOrPingAfterSensitiveInput > 0 || network.queryBearingGetAfterSensitiveForm > 0 ||
      (dataLeak.credentialLikeTextFieldCount > 0 && dataLeak.localFormWithJsSinkIndicator) ||
      (dataLeak.scriptNetworkSinkCount > 0 && dataLeak.dynamicEndpointAssemblyCount > 0) ||
      network.requestsAfterFormSubmit >= 3 || network.requestsAfterPasswordFocus >= 3 ||
      temporal.formSubmitThenThirdPartyCount >= 3) return "DATA_EXFILTRATION";
    if (toArray(signals.foundBankingKeywords).length > 0 && (signals.hasPasswordField || signals.hasOTP)) return "FAKE_BANKING";
    if (toArray(signals.foundStoreKeywords).length > 0 && toArray(signals.apkLinks).length > 0) return "FAKE_APP_STORE";
    if (toArray(signals.apkLinks).length > 0) return "MALICIOUS_APK";
    return Object.entries(categoryScores).sort((a, b) => b[1] - a[1])[0]?.[0] || "SAFE";
  }

  function buildToolResults(outputs, allEvidence) {
    const names = outputs.map((output) => output.name).concat("DECISION_COMBINER");
    return Array.from(new Set(names)).map((name) => {
      const evidence = allEvidence.filter((item) => item.tool === name);
      const score = Math.min(100, evidence.reduce((total, item) => total + effectivePoints(item), 0));
      return {
        tool: name,
        score: clampScore(score),
        confidence: evidence.length ? roundConfidence(weightedConfidence(evidence)) : 0,
        status: evidence.length ? "FINDINGS" : "CLEAR",
        findingCount: evidence.length,
        topEvidence: evidence.sort((a, b) => effectivePoints(b) - effectivePoints(a)).slice(0, 3).map((item) => item.message)
      };
    });
  }

  function selectReasons(evidence, policy) {
    return unique(evidence.slice().sort((a, b) => a.priority - b.priority || effectivePoints(b) - effectivePoints(a))
      .slice(0, policy.combiner.maximumReasons).map((item) => item.message));
  }

  function calculateConfidence(evidence, signals, level) {
    if (evidence.length === 0) {
      return signals.isTrustedDomain || signals.isSearchEnginePage ? 0.97 : 0.78;
    }
    let confidence = weightedConfidence(evidence);
    if (level === "HIGH_RISK" && evidence.filter((item) => item.decisive).length >= 2) {
      confidence = Math.max(confidence, 0.94);
    }
    return roundConfidence(confidence);
  }

  function weightedConfidence(evidence) {
    const totalWeight = evidence.reduce((total, item) => total + Math.max(1, item.weight), 0);
    return evidence.reduce((total, item) => total + item.confidence * Math.max(1, item.weight), 0) / totalWeight;
  }

  function finalizeEarlySafe(reason, outputs, policy, confidence) {
    return {
      score: 0,
      riskScore: 0,
      level: "SAFE",
      category: "SAFE",
      confidence,
      decisionTier: "NO_FINDINGS",
      reasons: [reason],
      evidence: [],
      toolResults: buildToolResults(outputs, []),
      policyVersion: policy.version,
      shouldWarn: false,
      source: "LOCAL_MODEL"
    };
  }

  function finding(id, toolName, category, weight, confidence, severity, message, decisive) {
    const configuredWeight = activePolicy.weights && Number(activePolicy.weights[id]);
    const finalWeight = Number.isFinite(configuredWeight) ? configuredWeight : weight;
    const configuredPriority = activePolicy.priorities && Number(activePolicy.priorities[id]);
    const priority = Number.isFinite(configuredPriority) ? configuredPriority : defaultPriority(toolName, id);
    return { id, tool: toolName, category, weight: finalWeight, confidence, priority, severity, message, decisive: Boolean(decisive) };
  }

  function tool(name, evidence) {
    return { name, evidence };
  }

  function publicEvidence(item) {
    return {
      id: item.id,
      tool: item.tool,
      category: item.category,
      priority: item.priority,
      points: Math.round(effectivePoints(item)),
      confidence: roundConfidence(item.confidence),
      severity: item.severity,
      message: item.message,
      decisive: item.decisive
    };
  }

  function effectivePoints(item) {
    return item.weight * item.confidence;
  }

  function addKeywordFinding(evidence, signals, property, category, weight, message) {
    if (!signals.isTrustedDomain && toArray(signals[property]).length > 0) {
      evidence.push(finding(`${category}_LANGUAGE`, "CONTENT_ANALYZER", category, weight, 0.68, "medium", message));
    }
  }

  function getDecisionTier(evidence) {
    if (evidence.some((item) => item.priority === 1)) return "OBSERVED_DATA_FLOW";
    if (evidence.some((item) => item.priority === 2)) return "CONTEXT_OR_INTENT";
    if (evidence.some((item) => item.priority === 3)) return "CONTENT_CATEGORY";
    return "NO_FINDINGS";
  }

  function defaultPriority(toolName, id) {
    if (["SENSITIVE_HTTP_FORM", "SENSITIVE_HTTP_PAGE_FORM", "PASSWORD_CROSS_DOMAIN", "SENSITIVE_CROSS_DOMAIN", "SENSITIVE_GENERIC_CROSS_DOMAIN"].includes(id)) return 1;
    if (toolName === "NETWORK_ANALYZER" && id !== "MANY_INSECURE_REQUESTS" && id !== "THIRD_PARTY_FORM_WRITE") return 1;
    if (toolName === "CONTENT_ANALYZER") return 3;
    return 2;
  }

  function applyScoreFloors(score, evidence, policy) {
    const floors = policy.scoreFloors || {};
    const evidenceFloor = evidence.reduce((maximum, item) => {
      const floor = Number(floors[item.id]);
      return Number.isFinite(floor) ? Math.max(maximum, floor) : maximum;
    }, 0);
    return Math.max(score, evidenceFloor);
  }

  function levelFromScore(score, policy) {
    if (score >= policy.thresholds.highRisk) return "HIGH_RISK";
    if (score >= policy.thresholds.suspicious) return "SUSPICIOUS";
    return "SAFE";
  }

  function mergePolicy(raw) {
    const policy = raw && typeof raw === "object" ? raw : {};
    return {
      ...DEFAULT_POLICY,
      ...policy,
      thresholds: { ...DEFAULT_POLICY.thresholds, ...(policy.thresholds || {}) },
      weights: { ...(DEFAULT_POLICY.weights || {}), ...(policy.weights || {}) },
      priorities: { ...(DEFAULT_POLICY.priorities || {}), ...(policy.priorities || {}) },
      scoreFloors: { ...(DEFAULT_POLICY.scoreFloors || {}), ...(policy.scoreFloors || {}) },
      combiner: { ...DEFAULT_POLICY.combiner, ...(policy.combiner || {}) }
    };
  }

  function dataLeakOf(signals) {
    return signals.dataLeakSignals || {};
  }

  function networkOf(signals) {
    return signals.networkSignals || {};
  }

  function temporalOf(signals) {
    return signals.temporalSignals || networkOf(signals).temporalSignals || {};
  }

  function toArray(value) {
    return Array.isArray(value) ? value.filter(Boolean) : [];
  }

  function unique(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function clampScore(value) {
    return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
  }

  function roundConfidence(value) {
    return Math.max(0, Math.min(1, Math.round((Number(value) || 0) * 100) / 100));
  }

  function isOfficialAppStore(domain) {
    return ["play.google.com", "apps.apple.com", "galaxystore.samsung.com", "apps.samsung.com"]
      .some((official) => isDomainMatch(domain, official));
  }

  function isDomainMatch(domain, expected) {
    return domain === expected || String(domain || "").endsWith(`.${expected}`);
  }

  function hasBrandImpersonationPattern(domain) {
    return /(g00gle|faceb00k|paypa[l1i]|micros0ft|samsunng|app1e)/i.test(domain);
  }

  function isFinanceOrNewsSafeContext(signals) {
    const domain = String(signals.domain || "");
    return signals.isTrustedDomain && (
      domain.includes("finance.yahoo.com") || domain.endsWith("set.or.th") ||
      domain.endsWith("sec.or.th") || domain.endsWith("bot.or.th")
    );
  }

  return {
    evaluate,
    DEFAULT_POLICY,
    analyzers: {
      analyzeDomain,
      analyzeCredentials,
      analyzeForms,
      analyzeScripts,
      analyzeDownloads,
      analyzeContent,
      analyzeNetwork
    }
  };
});
