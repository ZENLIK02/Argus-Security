(function exposeArgusEvidencePolicy(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusEvidencePolicy = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createEvidencePolicy() {
  "use strict";

  const POLICY_VERSION = "evidence-first-v5";
  const REPORT_SCHEMA_VERSION = "5";
  const STATES = Object.freeze(["SAFE", "MONITORING", "UNCERTAIN", "RISKY_CONTEXT", "SUSPICIOUS", "HIGH_RISK"]);

  const DIRECT_RULES = new Map([
    ["SENSITIVE_HTTP_FORM", "Sensitive credentials can be submitted over HTTP."],
    ["SENSITIVE_HTTP_PAGE_FORM", "Sensitive credentials can be submitted from an HTTP page."],
    ["PASSWORD_CROSS_DOMAIN", "A password form targets an unknown cross-site destination."],
    ["SENSITIVE_CROSS_DOMAIN", "OTP, payment, or credential data targets an unknown cross-site destination."],
    ["SENSITIVE_GENERIC_CROSS_DOMAIN", "A sensitive form targets an unknown cross-site destination."],
    ["UNENCRYPTED_SENSITIVE_WRITE", "An HTTP write followed sensitive interaction."],
    ["CROSS_DOMAIN_SENSITIVE_WRITE", "An unknown cross-site write followed sensitive interaction."],
    ["BEACON_AFTER_SENSITIVE_INPUT", "An unknown beacon followed sensitive interaction."],
    ["QUERY_GET_AFTER_SENSITIVE_FORM", "An unknown query-bearing request followed sensitive form submission."],
    ["OBSERVED_UNPROTECTED_EXFILTRATION", "Sensitive data flow was observed over an unprotected channel."],
    ["HTTP_APK", "An executable download is delivered over HTTP."],
    ["THIRD_PARTY_APK", "An executable download is delivered by an unknown third party."],
    ["REPUTATION_BLOCKLISTED", "This site appears on a known phishing or malware blocklist."],
    // Legacy alias from the codex fork; recognized for old reports, never emitted here.
    ["REPUTATION_CONFIRMED_MALICIOUS", "A configured threat-intelligence source identifies this destination as malicious."],
    ["HOMOGLYPH_BRAND_DOMAIN", "The domain uses look-alike characters to visually imitate a known brand."]
  ]);

  const GROUPS = Object.freeze({
    SENSITIVE_INPUT: new Set(["PASSWORD_UNKNOWN_DOMAIN", "OTP_UNKNOWN_DOMAIN", "DISGUISED_CREDENTIAL_FIELD", "FULL_CREDENTIAL_FLOW", "BANK_PASSWORD_COMBO", "BANK_OTP_COMBO"]),
    UNKNOWN_WRITE_DESTINATION: new Set(["THIRD_PARTY_FORM_WRITE", "POST_SUBMIT_THIRD_PARTY", "POST_PASSWORD_THIRD_PARTY"]),
    DYNAMIC_ENDPOINT: new Set(["DYNAMIC_ENDPOINT", "SCRIPT_NETWORK_EXTERNAL_HINT", "DISGUISED_FORM_JS_SINK", "FORM_READ_NETWORK_RELAY", "ENCODED_SENSITIVE_RELAY"]),
    HIDDEN_CREDENTIAL_FRAME: new Set(["HIDDEN_FRAME_WITH_CREDENTIALS", "UNSANDBOXED_FRAME_CREDENTIAL_PAGE"]),
    POST_INTERACTION_BEACON: new Set(["EXFILTRATION_SEQUENCE", "POST_SUBMIT_REDIRECT"]),
    INSECURE_TRANSPORT: new Set(["HTTP_FORM", "UNENCRYPTED_FORM_WRITE", "SENSITIVE_MIXED_ACTIVE_CONTENT"]),
    MALICIOUS_DOWNLOAD: new Set(["APK_HREF", "FAKE_STORE_APK_COMBO", "FAKE_STORE_THIRD_PARTY_APK", "FAKE_STORE_CREDENTIAL_APK", "POST_SUBMIT_DOWNLOAD"]),
    CONSENT_MANIPULATION: new Set(["POPUP_MESSAGE_RELAY", "POPUP_EXTERNAL_RELAY", "WILDCARD_MESSAGE_RELAY"]),
    CROSS_DOMAIN_FORM: new Set(["CROSS_DOMAIN_FORM"]),
    CLIPBOARD_FILE_COLLECTION: new Set(["CLIPBOARD_ACCESS", "FILE_METADATA_ACCESS", "RECOVERY_TEXT_DATA_MOVEMENT", "RECOVERY_SECRET_RELAY", "STORAGE_OR_COOKIE_RELAY"]),
    // Decisive credential-phishing combinations from the engine (brand-lookalike or
    // multi-lexical credential flows, fake-bank full flow). Without these, a
    // same-origin phishing page — no cross-domain/HTTP form and no observed network
    // write yet — collapsed to model-only and read SAFE. As a non-observed
    // behavioral group it surfaces as MONITORING and escalates to SUSPICIOUS only
    // when correlated with a second, observed group (F12).
    CREDENTIAL_PHISHING: new Set(["SUSPICIOUS_DOMAIN_CREDENTIAL_FLOW", "LEXICAL_CREDENTIAL_CLUSTER", "FAKE_BANK_FULL_FLOW"]),
    // Offline brand-lookalike (typosquat / credential-context combosquat). A
    // non-observed behavioral group: surfaces as MONITORING on its own and
    // correlates with credential/observed groups. The high-precision HOMOGLYPH case
    // is handled separately as DIRECT evidence.
    BRAND_IMPERSONATION: new Set(["DOMAIN_BRAND_LOOKALIKE"]),
    CLAIMED_IDENTITY: new Set(["CLAIMED_BRAND_IDENTITY"]),
    DOMAIN_IDENTITY_MISMATCH: new Set(["DOMAIN_IDENTITY_MISMATCH", "DECEPTIVE_BRAND_SUBDOMAIN", "BRAND_HOMOGRAPH_OR_TYPOSQUAT"]),
    HIGH_VALUE_CONTEXT: new Set(["HIGH_VALUE_CONTEXT"]),
    VISUAL_IDENTITY: new Set(["VISUAL_BRAND_MATCH"]),
    // DOMAIN_BRAND_LOOKALIKE deliberately absent here: it already forms the
    // BRAND_IMPERSONATION group, and one lookalike detection must not count as two
    // independent groups toward correlation.
    DOMAIN_RISK: new Set(["DOMAIN_PUNYCODE", "URL_OBFUSCATION", "URL_EXCESSIVE_SUBDOMAINS", "DOMAIN_HIGH_DIGIT_RATIO", "DECEPTIVE_BRAND_SUBDOMAIN", "BRAND_HOMOGRAPH_OR_TYPOSQUAT"]),
    GAMBLING_OPERATOR: new Set(["GAMBLING_CONTENT"]),
    SENSITIVE_ACTION: new Set(["SENSITIVE_ACTION_SURFACE"]),
    // MALICIOUS reputation verdicts are direct-only (REPUTATION_BLOCKLISTED); this
    // group carries the graded, non-direct verdicts.
    EXTERNAL_REPUTATION: new Set(["REPUTATION_RISKY_CONTEXT", "REPUTATION_RISKY_CATEGORY"])
  });

  // A raw .apk download link (APK_HREF) is deliberately NOT weak: it belongs to the
  // observed MALICIOUS_DOWNLOAD group, so an APK-only page must surface as
  // MONITORING rather than collapse to SAFE via the low-context branch (F13).
  const WEAK_IDS = new Set([
    "PASSWORD_UNKNOWN_DOMAIN", "OTP_UNKNOWN_DOMAIN", "LOGIN_LANGUAGE", "GAMBLING_CONTENT", "ADULT_CONTENT",
    "AGGRESSIVE_AD_LAYOUT", "POPUP_ABUSE_LANGUAGE", "MISSING_BROWSER_PROTECTIONS", "THIRD_PARTY_SCRIPT_NO_INTEGRITY",
    "EXTERNAL_SCRIPT_CREDENTIAL_PAGE", "MANY_INSECURE_REQUESTS", "DOMAIN_LONG", "DOMAIN_HYPHENS", "DOMAIN_RISK_WORDS",
    "URL_UNUSUALLY_LONG", "URL_EXCESSIVE_SUBDOMAINS"
  ]);

  const OBSERVED_GROUPS = new Set([
    "UNKNOWN_WRITE_DESTINATION", "POST_INTERACTION_BEACON", "INSECURE_TRANSPORT",
    "MALICIOUS_DOWNLOAD", "CROSS_DOMAIN_FORM"
  ]);

  function decide(input) {
    const legacy = input && input.legacyRisk || {};
    const evidence = Array.isArray(legacy.evidence) ? legacy.evidence : [];
    const model = adaptModel(legacy.modelAnalysis, legacy.score);
    const context = input && input.context || {};
    const engineDirect = evidence.filter((item) => DIRECT_RULES.has(item.id)).map((item) => structuredEvidence(item, context, DIRECT_RULES.get(item.id)));
    // Only service-worker-observed network counters can create telemetry direct evidence.
    // Static script patterns remain non-direct and retain their conservative cap.
    const telemetryDirect = directEvidenceFromTelemetry(context);
    // A domain-reputation MALICIOUS verdict is high-confidence direct evidence available
    // at load time — it catches real scam sites even when no cross-domain/HTTP write
    // is browser-observable (e.g. a phishing page posting to its own HTTPS domain).
    const reputationDirect = directEvidenceFromReputation(context);
    const direct = uniqueDirectEvidence(engineDirect.concat(telemetryDirect).concat(reputationDirect));
    const reputationHit = reputationDirect.length > 0;
    const evidenceGroups = collectGroups(evidence);
    const behavioralGroups = evidenceGroups.filter((group) => group !== "SENSITIVE_INPUT");
    const observedGroups = evidenceGroups.filter((group) => OBSERVED_GROUPS.has(group));
    const weakEvidence = evidence.filter((item) => WEAK_IDS.has(item.id));
    const modelOnly = direct.length === 0 && behavioralGroups.length === 0;
    const adsOnly = evidence.length > 0 && evidence.every((item) => /AD_|ADS|AGGRESSIVE_AD|POPUP_ABUSE/.test(item.id));
    const categoryOnly = evidence.length > 0 && evidence.every((item) => /CONTENT|GAMBLING|ADULT|LANGUAGE/.test(item.id));
    const lowContextOnly = evidence.length > 0 && evidence.every((item) => WEAK_IDS.has(item.id) || /CONTENT|GAMBLING|ADULT|LANGUAGE/.test(item.id));
    const gamblingOperator = evidenceGroups.includes("GAMBLING_OPERATOR");
    const sensitiveAction = evidenceGroups.includes("SENSITIVE_ACTION");
    const sensitiveInteractionObserved = Boolean(context.sensitiveInteractionObserved);
    const identity = context.identitySignals && typeof context.identitySignals === "object" ? context.identitySignals : {};
    const identityMismatch = evidenceGroups.includes("DOMAIN_IDENTITY_MISMATCH");
    const highValueContext = evidenceGroups.includes("HIGH_VALUE_CONTEXT") && Boolean(identity.highValueContext);
    const domainRisk = evidenceGroups.includes("DOMAIN_RISK");
    const externalRisk = evidenceGroups.includes("EXTERNAL_REPUTATION");
    const sensitivityMode = normalizeSensitivityMode(context.sensitivityMode);
    const reputationVerdict = String(context.reputation && context.reputation.verdict || "UNKNOWN").toUpperCase();
    const riskContext = gamblingOperator ? "GAMBLING" : String(identity.primaryContext || "UNKNOWN");
    const contextRisk = !context.isTrustedDomain && !identity.officialDomain && (
      gamblingOperator ||
      reputationVerdict === "RISKY_CONTEXT" ||
      sensitivityMode === "PROTECTIVE" && (identityMismatch || highValueContext) ||
      sensitivityMode === "BALANCED" && (Boolean(identity.strongMismatch) || highValueContext && sensitiveAction) ||
      sensitivityMode === "CONSERVATIVE" && identityMismatch && sensitiveAction
    );
    const identitySuspicious = identityMismatch && sensitiveAction && (domainRisk || externalRisk || observedGroups.length > 0);
    // Standard SUSPICIOUS: two independent behavioral groups with at least one
    // browser-OBSERVED. A brand look-alike (typosquat/combosquat, or a registry
    // homograph/typosquat match) that also collects credentials/OTP/payment is a
    // high-confidence phishing pattern on its own — it escalates to SUSPICIOUS
    // without needing observed network behavior (P3).
    const correlatedBehavior = evidenceGroups.length >= 2 && observedGroups.length >= 1;
    const brandLookalikePresent = evidenceGroups.includes("BRAND_IMPERSONATION") ||
      evidence.some((item) => item.id === "BRAND_HOMOGRAPH_OR_TYPOSQUAT");
    const impersonationPhishing = brandLookalikePresent &&
      (evidenceGroups.includes("SENSITIVE_INPUT") || evidenceGroups.includes("CREDENTIAL_PHISHING"));
    const phaseFinal = ["FINAL", "INTERACTION_FINAL"].includes(String(context.scanPhase || "").toUpperCase());
    let status = "SAFE";
    let score = 0;
    let confidence = "HIGH";
    let evidenceLevel = "NONE";

    if (!phaseFinal) {
      status = "MONITORING";
      score = 0;
      confidence = "LOW";
      evidenceLevel = direct.length ? "DIRECT_PENDING" : evidenceGroups.length ? "CORRELATED_PENDING" : "INCOMPLETE";
    } else if (direct.length > 0) {
      status = "HIGH_RISK";
      // A reputation blocklist match is top-severity regardless of the local score.
      score = Math.max(reputationHit ? 95 : 70, Math.min(100, Number(legacy.score) || 70));
      confidence = "HIGH";
      evidenceLevel = reputationHit ? "DIRECT_REPUTATION" : "DIRECT";
    } else if ((context.isTrustedDomain || context.isSearchEnginePage || identity.officialDomain) && observedGroups.length === 0) {
      status = "SAFE";
      score = 0;
      confidence = "HIGH";
      evidenceLevel = "TRUSTED_CONTEXT";
    } else if (correlatedBehavior || impersonationPhishing || identitySuspicious) {
      status = "SUSPICIOUS";
      score = Math.max(60, Math.min(69, Number(legacy.score) || 60));
      confidence = evidenceGroups.length >= 3 ? "HIGH" : "MEDIUM";
      evidenceLevel = impersonationPhishing && !correlatedBehavior && !identitySuspicious ? "BRAND_IMPERSONATION_PHISHING" : "CORRELATED";
    } else if (contextRisk) {
      status = "RISKY_CONTEXT";
      const highConfidenceContext = sensitiveAction || reputationVerdict === "RISKY_CONTEXT";
      score = highConfidenceContext
        ? Math.max(48, Math.min(59, Number(legacy.score) || 48))
        : Math.max(35, Math.min(47, Number(legacy.score) || 35));
      confidence = highConfidenceContext ? "HIGH" : "MEDIUM";
      evidenceLevel = sensitiveAction ? "CONTEXT_WITH_SENSITIVE_ACTION" : "IDENTITY_OR_CATEGORY_RISK";
    } else if (adsOnly || categoryOnly || lowContextOnly) {
      status = "SAFE";
      score = 0;
      confidence = "MEDIUM";
      evidenceLevel = "WEAK_CONTEXT";
    } else if (modelOnly && model.score >= 85) {
      // A high local model score with NO independent behavioral or direct evidence
      // is not actionable. Keep it non-warning and visually SAFE. When real
      // behavioral evidence exists, a confident model must not downgrade it here —
      // it falls through to the MONITORING branch instead.
      status = "SAFE";
      score = 0;
      confidence = "MEDIUM";
      evidenceLevel = "MODEL_ONLY";
    } else if (behavioralGroups.length === 1 || evidenceGroups.length > 0 || model.score >= 35 || weakEvidence.length > 0) {
      status = "MONITORING";
      score = modelOnly
        ? capModelOnlyScore(model.score)
        : observedGroups.length === 0
          ? capSingleGroupScore(legacy.score, model.score)
          : capWeakScore(legacy, model, evidence);
      confidence = "LOW";
      evidenceLevel = observedGroups.length === 0 && behavioralGroups.length > 0 ? "STATIC_INTENT" : behavioralGroups.length ? "SINGLE_GROUP" : modelOnly ? "MODEL_ONLY" : "WEAK_CONTEXT";
    }

    const overlayAllowed = phaseFinal && status === "HIGH_RISK" && direct.length > 0;
    const warningAllowed = overlayAllowed
      || (phaseFinal && status === "RISKY_CONTEXT")
      || (phaseFinal && status === "SUSPICIOUS" && (correlatedBehavior || impersonationPhishing || identitySuspicious));
    const warningStage = status === "RISKY_CONTEXT" ? (sensitiveInteractionObserved ? "INTERACTION" : "BADGE") : status === "SUSPICIOUS" || status === "HIGH_RISK" ? "INTERACTION" : "NONE";
    const reasons = buildReasons(status, direct, evidenceGroups, weakEvidence, modelOnly, riskContext, identity);
    if (status === "SUSPICIOUS" && impersonationPhishing && !correlatedBehavior) {
      reasons.unshift("The domain imitates a known brand and also collects sensitive login or payment information.");
    }
    return {
      status, level: status, score, riskScore: score, confidence, warningAllowed, overlayAllowed,
      shouldWarn: warningAllowed, evidenceLevel, evidenceIds: unique(evidence.map((item) => item.id)),
      evidenceGroups, observedEvidenceGroups: observedGroups, correlatedEvidenceGroups: evidenceGroups.length, directEvidence: direct,
      engineDirectEvidenceIds: engineDirect.map((item) => item.id), telemetryDirectEvidenceIds: telemetryDirect.map((item) => item.id),
      reputationDirectEvidenceIds: reputationDirect.map((item) => item.id),
      reasons, modelOnly, model, riskContext, warningStage, sensitivityMode,
      claimedBrands: toArray(identity.claimedBrands).slice(0, 5).map((brand) => ({
        brandId: String(brand && brand.brandId || "").slice(0, 80),
        displayName: String(brand && brand.displayName || "").slice(0, 120),
        contexts: toArray(brand && brand.contexts).slice(0, 5).map(String),
        official: Boolean(brand && brand.official)
      })),
      identityEvidence: {
        domainMismatch: identityMismatch, visualMatch: Boolean(identity.visualMatch),
        deceptiveSubdomain: Boolean(identity.deceptiveSubdomain), homographOrTyposquat: Boolean(identity.homographOrTyposquat),
        lookalikeKind: normalizeLookalikeKind(identity.lookalikeKind)
      },
      policyVersion: POLICY_VERSION, reportSchemaVersion: REPORT_SCHEMA_VERSION,
      source: "EVIDENCE_FIRST_POLICY"
    };
  }

  function collectGroups(evidence) {
    const groups = [];
    for (const [group, ids] of Object.entries(GROUPS)) {
      if (evidence.some((item) => ids.has(item.id))) groups.push(group);
    }
    return groups;
  }

  function structuredEvidence(item, context, explanation) {
    return {
      id: item.id, type: item.category || "SECURITY_BEHAVIOR", severity: "critical",
      timestamp: context.timestamp || new Date().toISOString(), source: item.tool || "ARGUS_ENGINE",
      destination: destinationFor(item.id, context), destinationRole: destinationRoleFor(item.id, context),
      navigationId: context.navigationId || "unknown", frameId: Number(context.frameId) || 0,
      scanPhase: context.scanPhase || "FINAL", explanation
    };
  }

  function directEvidenceFromTelemetry(context) {
    const network = context.networkSignals || {};
    const temporal = network.temporalSignals || {};
    const candidates = [
      ["UNENCRYPTED_SENSITIVE_WRITE", Number(network.insecureSensitiveWriteRequests) > 0 || Number(temporal.unencryptedSensitiveWriteCount) > 0],
      ["CROSS_DOMAIN_SENSITIVE_WRITE", Number(network.crossDomainSensitiveWriteRequests) > 0 || Number(temporal.crossDomainSensitiveWriteCount) > 0],
      ["BEACON_AFTER_SENSITIVE_INPUT", Number(network.beaconOrPingAfterSensitiveInput) > 0 || Number(temporal.beaconAfterSensitiveInputCount) > 0],
      ["QUERY_GET_AFTER_SENSITIVE_FORM", Number(network.queryBearingGetAfterSensitiveForm) > 0]
    ];
    return candidates
      .filter(([, observed]) => observed)
      .map(([id]) => structuredEvidence({ id, category: "DATA_EXFILTRATION", tool: "NETWORK_TELEMETRY" }, context, DIRECT_RULES.get(id)));
  }

  // Domain-reputation verdict supplied by the service worker (via the reputation
  // client). Only a positive MALICIOUS/listed verdict creates direct evidence;
  // graded RISKY_CONTEXT verdicts flow through the EXTERNAL_REPUTATION group and
  // anything else (unknown/unavailable/trusted) produces none.
  function directEvidenceFromReputation(context) {
    const reputation = context.reputation || {};
    const verdict = String(reputation.verdict || "").toUpperCase();
    if (!reputation.listed && verdict !== "MALICIOUS") return [];
    const id = "REPUTATION_BLOCKLISTED";
    return [structuredEvidence(
      { id, category: "REPUTATION", tool: String(reputation.source || "REPUTATION_FEED").slice(0, 40) },
      context,
      DIRECT_RULES.get(id)
    )];
  }

  function uniqueDirectEvidence(items) {
    const seen = new Set();
    return items.filter((item) => {
      const key = `${item.id}:${item.source}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function destinationFor(id, context) {
    const network = context.networkSignals || {};
    if (/APK/.test(id)) return first(network.executableDownloadDomains);
    if (/CROSS_DOMAIN|BEACON|QUERY_GET/.test(id)) return first(network.unknownSensitiveDestinations);
    return "not-retained";
  }

  function destinationRoleFor(id, context) {
    if (/APK/.test(id)) return "EXECUTABLE_DOWNLOAD_SOURCE";
    if (/BEACON|QUERY_GET/.test(id)) return "UNKNOWN_BEACON";
    if (/CROSS_DOMAIN/.test(id)) return "UNKNOWN_WRITE_DESTINATION";
    if (/HTTP/.test(id) || /UNENCRYPTED/.test(id)) return "FIRST_PARTY_WRITE";
    return first(context.destinationRoles) || "UNKNOWN_WRITE_DESTINATION";
  }

  function adaptModel(analysis, fallbackScore) {
    const raw = analysis || {};
    const score = Math.max(0, Math.min(100, Number(raw.score ?? fallbackScore) || 0));
    return {
      overallRiskProbability: Math.round(score) / 100, score: Math.round(score),
      behaviorProbabilitiesAvailable: false, confidence: raw.evidenceGroups >= 2 ? "MEDIUM" : "LOW",
      modelVersion: String(raw.version || "unknown")
    };
  }

  function capWeakScore(legacy, model, evidence) {
    const ids = new Set(evidence.map((item) => item.id));
    const categoryOnly = evidence.length > 0 && evidence.every((item) => /CONTENT|GAMBLING|ADULT|LANGUAGE/.test(item.id));
    const adsOnly = evidence.length > 0 && evidence.every((item) => /AD_|ADS|AGGRESSIVE_AD|POPUP_ABUSE/.test(item.id));
    if (adsOnly) return Math.min(5, Number(legacy.score) || 5);
    if (categoryOnly) return Math.min(10, Number(legacy.score) || 10);
    if (ids.size === 0) return model.score > 0 ? Math.min(5, Math.max(1, Math.round(model.score * 0.05))) : 0;
    return Math.min(34, Math.max(1, Number(legacy.score) || Math.round(model.score * 0.34)));
  }

  function capModelOnlyScore(modelScore) {
    const score = Number(modelScore) || 0;
    return score > 0 ? Math.min(5, Math.max(1, Math.round(score * 0.05))) : 0;
  }

  function capSingleGroupScore(legacyScore, modelScore) {
    const strongest = Math.max(Number(legacyScore) || 0, Number(modelScore) || 0);
    return strongest > 0 ? Math.min(10, Math.max(1, Math.round(strongest * 0.1))) : 0;
  }

  function buildReasons(status, direct, groups, weak, modelOnly, riskContext, identity) {
    if (status === "HIGH_RISK") return direct.slice(0, 3).map((item) => item.explanation);
    if (status === "SUSPICIOUS") return [`Independent behavioral evidence correlated: ${groups.join(", ")}.`, "Harmful behavior is suspected but direct transmission was not confirmed."];
    if (status === "RISKY_CONTEXT") {
      const brandNames = toArray(identity.claimedBrands).map((brand) => brand.displayName || brand.brandId).filter(Boolean).slice(0, 3);
      const subject = brandNames.length ? `The page claims to represent ${brandNames.join(", ")}, but the domain is not approved.` : `An unverified ${String(riskContext || "sensitive").toLowerCase().replace(/_/g, " ")} context was detected.`;
      return groups.includes("SENSITIVE_ACTION")
        ? [subject, "Use caution before login, payment, identity, wallet, or recovery actions; fraud was not confirmed."]
        : [subject, "This is an early caution and does not claim that fraud or data theft was confirmed."];
    }
    if (status === "UNCERTAIN") return ["The local model is uncertain, but no direct or sufficiently correlated harmful behavior was observed."];
    if (status === "MONITORING") return [modelOnly ? "Argus is monitoring weak or model-only signals; no warning is allowed." : "Argus is monitoring incomplete behavioral evidence; no direct violation is confirmed."];
    return [weak.length ? "Only weak contextual signals were observed; they cannot create a warning." : "No meaningful behavioral security evidence was observed."];
  }

  function first(value) { return Array.isArray(value) && value.length ? String(value[0]) : "not-retained"; }
  function toArray(value) { return Array.isArray(value) ? value.filter(Boolean) : []; }
  function normalizeSensitivityMode(value) {
    const mode = String(value || "BALANCED").toUpperCase();
    return ["CONSERVATIVE", "BALANCED", "PROTECTIVE"].includes(mode) ? mode : "BALANCED";
  }
  function normalizeLookalikeKind(value) {
    const kind = String(value || "NONE").toUpperCase();
    return ["HOMOGLYPH", "TYPOSQUAT", "COMBOSQUAT", "NONE"].includes(kind) ? kind : "NONE";
  }
  function unique(values) { return Array.from(new Set(values.filter(Boolean))); }

  return { POLICY_VERSION, REPORT_SCHEMA_VERSION, STATES, DIRECT_RULES, GROUPS, OBSERVED_GROUPS, decide, adaptModel };
});
