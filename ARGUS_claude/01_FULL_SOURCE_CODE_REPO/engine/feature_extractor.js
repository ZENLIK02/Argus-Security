(function exposeArgusFeatures(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.ArgusFeatureExtractor = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createArgusFeatures() {
  "use strict";

  const FEATURE_NAMES = [
    "untrusted_domain", "search_engine_page", "insecure_page", "password_field", "otp_field",
    "login_language", "suspicious_domain", "brand_like_domain", "bank_language", "store_language",
    "apk_link", "gambling_or_adult", "ad_heavy", "sensitive_form", "cross_domain_form",
    "http_form", "password_cross_domain_form", "sensitive_cross_domain_form", "sensitive_http_form",
    "credential_like_field", "hidden_frame", "external_script_credential_page", "script_network_sink",
    "external_endpoint_hint", "dynamic_endpoint", "form_value_read", "formdata_read", "storage_secret_write",
    "cookie_read", "encoded_payload", "websocket_send", "wildcard_postmessage", "clipboard_or_file_access",
    "missing_security_headers", "mixed_content", "insecure_active_content", "third_party_script_no_integrity",
    "unsandboxed_third_party_frame", "insecure_sensitive_write", "cross_domain_sensitive_write",
    "beacon_after_sensitive_input", "query_get_after_sensitive_form", "insecure_write_after_form",
    "third_party_activity_after_form", "third_party_activity_after_password", "cross_domain_redirect_after_form",
    "download_after_form", "credential_flow_combo", "fake_store_apk_combo", "sensitive_form_transport_combo",
    "form_read_relay_combo", "storage_relay_combo", "encoded_relay_combo", "websocket_relay_combo",
    "postmessage_relay_combo", "unprotected_script_credential_combo", "mixed_sensitive_combo",
    "bank_credential_combo", "generic_http_form", "recovery_relay_combo", "url_long",
    "url_ip_host", "url_obfuscation", "url_excessive_subdomains", "domain_high_digit_ratio",
    "url_credential_path", "lexical_credential_combo", "secure_same_origin_auth", "content_only"
  ];

  function extract(signals) {
    const raw = signals && typeof signals === "object" ? signals : {};
    const leak = raw.dataLeakSignals || {};
    const network = raw.networkSignals || {};
    const temporal = network.temporalSignals || raw.temporalSignals || {};
    const security = raw.securitySignals || {};
    const lexical = raw.urlLexicalSignals || {};
    const untrusted = !raw.isTrustedDomain;
    const sensitivePage = Boolean(raw.hasPasswordField || raw.hasOTP || number(leak.sensitiveFormCount) > 0 || number(leak.credentialLikeTextFieldCount) > 0);
    const scriptSink = number(leak.scriptNetworkSinkCount) > 0;
    const endpointHint = arrayLength(leak.externalUrlHints) > 0;
    const formRead = Boolean(leak.formValueReadIndicator || leak.formDataReadIndicator);
    const storageReadWrite = Boolean(leak.sensitiveStorageWriteIndicator || leak.cookieReadIndicator);
    const lowPriorityContent = arrayLength(raw.foundGamblingKeywords) + arrayLength(raw.foundAdultKeywords) +
      arrayLength(raw.domainCategorySignals && raw.domainCategorySignals.gambling) +
      arrayLength(raw.domainCategorySignals && raw.domainCategorySignals.adult) > 0 || Boolean(raw.hasAdHeavySignal);
    const highContext = sensitivePage || arrayLength(raw.apkLinks) > 0 || number(leak.crossDomainFormActionCount) > 0 ||
      scriptSink || number(security.insecureActiveContentRequestCount) > 0 || number(network.writeRequestsAfterFormSubmit) > 0;

    const values = {
      untrusted_domain: bool(untrusted),
      search_engine_page: bool(raw.isSearchEnginePage),
      insecure_page: bool(raw.pageProtocol === "http:"),
      password_field: bool(raw.hasPasswordField),
      otp_field: bool(raw.hasOTP),
      login_language: bool(raw.hasLoginKeyword),
      suspicious_domain: bounded(arrayLength(raw.suspiciousDomainSignals), 3),
      brand_like_domain: bool(hasBrandPattern(raw.domain)),
      bank_language: bounded(arrayLength(raw.foundBankingKeywords), 3),
      store_language: bounded(arrayLength(raw.foundStoreKeywords), 3),
      apk_link: bounded(arrayLength(raw.apkLinks), 3),
      gambling_or_adult: bool(lowPriorityContent),
      ad_heavy: bool(raw.hasAdHeavySignal),
      sensitive_form: bounded(number(leak.sensitiveFormCount), 3),
      cross_domain_form: bounded(number(leak.crossDomainFormActionCount), 3),
      http_form: bounded(number(leak.httpFormActionCount), 3),
      password_cross_domain_form: bool(leak.passwordCrossDomainForm),
      sensitive_cross_domain_form: bool(leak.otpOrPaymentCrossDomainForm || (number(leak.sensitiveFormCount) > 0 && number(leak.crossDomainFormActionCount) > 0)),
      sensitive_http_form: bool(leak.passwordHttpForm || leak.otpOrPaymentHttpForm || leak.sameOriginSensitiveHttpForm || leak.httpPageWithSensitiveForm),
      credential_like_field: bounded(number(leak.credentialLikeTextFieldCount), 3),
      hidden_frame: bounded(number(leak.hiddenIframeCount), 3),
      external_script_credential_page: bool(number(leak.externalScriptCount) > 0 && sensitivePage),
      script_network_sink: bounded(number(leak.scriptNetworkSinkCount), 3),
      external_endpoint_hint: bounded(arrayLength(leak.externalUrlHints), 3),
      dynamic_endpoint: bounded(number(leak.dynamicEndpointAssemblyCount), 3),
      form_value_read: bool(leak.formValueReadIndicator),
      formdata_read: bool(leak.formDataReadIndicator),
      storage_secret_write: bool(leak.sensitiveStorageWriteIndicator),
      cookie_read: bool(leak.cookieReadIndicator),
      encoded_payload: bool(leak.encodedPayloadIndicator),
      websocket_send: bool(leak.webSocketSendIndicator),
      wildcard_postmessage: bool(leak.wildcardPostMessageIndicator),
      clipboard_or_file_access: bool(leak.clipboardReadIndicator || leak.fileMetadataHarvestIndicator),
      missing_security_headers: bounded(number(security.missingSecurityHeaderCount) / 5, 1),
      mixed_content: bounded(number(security.mixedContentRequestCount), 3),
      insecure_active_content: bounded(number(security.insecureActiveContentRequestCount), 3),
      third_party_script_no_integrity: bounded(number(security.thirdPartyScriptWithoutIntegrityCount), 4),
      unsandboxed_third_party_frame: bounded(number(security.unsandboxedThirdPartyIframeCount), 3),
      insecure_sensitive_write: bounded(number(network.insecureSensitiveWriteRequests), 3),
      cross_domain_sensitive_write: bounded(number(network.crossDomainSensitiveWriteRequests), 3),
      beacon_after_sensitive_input: bounded(number(network.beaconOrPingAfterSensitiveInput), 3),
      query_get_after_sensitive_form: bounded(number(network.queryBearingGetAfterSensitiveForm), 3),
      insecure_write_after_form: bounded(number(network.insecureWriteRequestsAfterFormSubmit), 3),
      third_party_activity_after_form: bounded(Math.max(number(network.requestsAfterFormSubmit), number(temporal.formSubmitThenThirdPartyCount)) / 3, 2),
      third_party_activity_after_password: bounded(number(network.requestsAfterPasswordFocus) / 3, 2),
      cross_domain_redirect_after_form: bounded(number(temporal.formSubmitThenCrossDomainRedirectCount), 3),
      download_after_form: bounded(number(temporal.downloadAfterFormSubmitCount), 3),
      credential_flow_combo: bool(untrusted && raw.hasPasswordField && raw.hasOTP && raw.hasLoginKeyword),
      fake_store_apk_combo: bool(untrusted && arrayLength(raw.foundStoreKeywords) > 0 && arrayLength(raw.apkLinks) > 0),
      sensitive_form_transport_combo: bool(sensitivePage && (number(leak.httpFormActionCount) > 0 || number(leak.crossDomainFormActionCount) > 0)),
      form_read_relay_combo: bool(sensitivePage && formRead && scriptSink),
      storage_relay_combo: bool(storageReadWrite && scriptSink && endpointHint),
      encoded_relay_combo: bool(sensitivePage && leak.encodedPayloadIndicator && scriptSink),
      websocket_relay_combo: bool(sensitivePage && leak.webSocketSendIndicator),
      postmessage_relay_combo: bool(sensitivePage && leak.wildcardPostMessageIndicator && scriptSink),
      unprotected_script_credential_combo: bool(sensitivePage && number(security.thirdPartyScriptWithoutIntegrityCount) > 0 && number(security.missingSecurityHeaderCount) >= 2),
      mixed_sensitive_combo: bool(sensitivePage && number(security.insecureActiveContentRequestCount) > 0),
      bank_credential_combo: bool(untrusted && arrayLength(raw.foundBankingKeywords) > 0 && raw.hasPasswordField && raw.hasOTP),
      generic_http_form: bool(number(leak.httpFormActionCount) > 0 && !sensitivePage),
      recovery_relay_combo: bool(number(leak.sensitiveTextareaCount) > 0 && (leak.clipboardReadIndicator || scriptSink)),
      url_long: bool(number(lexical.urlLength) >= 100),
      url_ip_host: bool(lexical.isDomainIP),
      url_obfuscation: bool(lexical.hasObfuscation || number(lexical.obfuscatedCharCount) >= 2 || lexical.hasAtSymbol),
      url_excessive_subdomains: bool(number(lexical.excessiveSubdomainCount) >= 2),
      domain_high_digit_ratio: bool(number(lexical.domainDigitRatio) >= 0.25),
      url_credential_path: bool(number(lexical.credentialPathWordCount) >= 1),
      lexical_credential_combo: bool(untrusted && number(lexical.lexicalRiskCount) >= 3 && (sensitivePage || raw.hasLoginKeyword)),
      secure_same_origin_auth: bool(
        sensitivePage && number(leak.formCount) > 0 && number(leak.crossDomainFormActionCount) === 0 &&
        number(leak.httpFormActionCount) === 0 && number(network.insecureSensitiveWriteRequests) === 0 &&
        number(network.crossDomainSensitiveWriteRequests) === 0 && number(lexical.lexicalRiskCount) < 3 &&
        security.hasContentSecurityPolicy && security.hasStrictTransportSecurity &&
        arrayLength(raw.foundBankingKeywords) === 0 && arrayLength(raw.foundStoreKeywords) === 0
      ),
      content_only: bool(lowPriorityContent && !highContext)
    };

    return values;
  }

  function vectorize(signals) {
    const values = extract(signals);
    return FEATURE_NAMES.map((name) => number(values[name]));
  }

  function independentEvidenceGroups(signals) {
    const f = extract(signals);
    return [
      f.suspicious_domain || f.brand_like_domain || f.lexical_credential_combo,
      f.password_field || f.otp_field || f.sensitive_form,
      f.cross_domain_form || f.http_form,
      f.script_network_sink || f.form_value_read || f.formdata_read,
      f.storage_secret_write || f.cookie_read,
      f.mixed_content || f.insecure_active_content,
      f.third_party_script_no_integrity || f.unsandboxed_third_party_frame,
      f.insecure_sensitive_write || f.cross_domain_sensitive_write || f.beacon_after_sensitive_input,
      f.apk_link || f.download_after_form,
      f.cross_domain_redirect_after_form
    ].filter(Boolean).length;
  }

  function predict(signals, model) {
    if (!model || !Array.isArray(model.weights) || model.weights.length !== FEATURE_NAMES.length) {
      return null;
    }
    const raw = vectorize(signals);
    let logit = number(model.bias);
    for (let index = 0; index < raw.length; index += 1) {
      const mean = number(model.means && model.means[index]);
      const scale = Math.max(0.000001, number(model.scales && model.scales[index]) || 1);
      logit += ((raw[index] - mean) / scale) * number(model.weights[index]);
    }
    const probability = sigmoid(logit);
    return {
      score: Math.round(probability * 100),
      probability: Math.round(probability * 10000) / 10000,
      evidenceGroups: independentEvidenceGroups(signals),
      version: String(model.version || "unknown")
    };
  }

  function sigmoid(value) {
    if (value >= 0) return 1 / (1 + Math.exp(-Math.min(value, 40)));
    const exp = Math.exp(Math.max(value, -40));
    return exp / (1 + exp);
  }

  function hasBrandPattern(domain) {
    return /(g00gle|faceb00k|paypa[l1i]|micros0ft|samsunng|app1e)/i.test(String(domain || ""));
  }

  function arrayLength(value) {
    return Array.isArray(value) ? value.filter(Boolean).length : 0;
  }

  function number(value) {
    return Number.isFinite(Number(value)) ? Number(value) : 0;
  }

  function bounded(value, maximum) {
    return Math.max(0, Math.min(maximum, number(value)));
  }

  function bool(value) {
    return value ? 1 : 0;
  }

  return { FEATURE_NAMES, extract, vectorize, independentEvidenceGroups, predict };
});
