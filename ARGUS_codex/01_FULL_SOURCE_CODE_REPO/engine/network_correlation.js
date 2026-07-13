(function exposeArgusNetworkCorrelation(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusNetworkCorrelation = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createNetworkCorrelation() {
  "use strict";

  const SENSITIVE_REQUEST_WINDOW_MS = 15000;

  // A beacon/ping to an unknown third-party destination is exfiltration-relevant
  // even before the sensitive interaction has been observed. The live
  // destination-role classifier only tags UNKNOWN_BEACON once the interaction is
  // known, so a pixel/ping that fires first would otherwise be dropped and the
  // correlation lost (the "stuck at 5/100" race). Recognize it here so a
  // candidate remembered before focus/submit can still correlate afterwards.
  function isUnknownBeaconDestination(details, isThirdParty, isKnownDestination) {
    const type = String(details && details.type || "");
    if (type !== "beacon" && type !== "ping") return false;
    if (!isThirdParty) return false;
    return !isKnownDestination;
  }

  function isCandidateRelevant(candidate) {
    return Boolean(
      candidate.isUnknownWrite ||
      candidate.isUnknownBeacon ||
      candidate.isQueryImage ||
      (candidate.isWriteRequest && candidate.isInsecure)
    );
  }

  // Pure decision: given a remembered request candidate and the interaction
  // trigger that just fired, return which sensitive counters it correlates into,
  // whether its destination should be retained, and the timeline events to emit.
  // Mirrors the service-worker live-path counting so live and retroactive
  // correlation produce identical evidence.
  function correlationEffects(candidate, trigger) {
    const empty = { accept: false, counters: {}, destination: false, timeline: [] };
    if (!candidate || candidate.correlated) return empty;
    // A sensitive focus (no form submit) only justifies beacon-style exfiltration.
    if (trigger === "SENSITIVE_FOCUS" && !candidate.isUnknownBeacon) return empty;

    const counters = {};
    const timeline = [];
    let destination = false;

    if (candidate.isUnknownWrite) {
      counters.requestsAfterFormSubmit = 1;
    }
    if (candidate.isWriteRequest) {
      counters.writeRequestsAfterFormSubmit = 1;
      if (candidate.isInsecure) counters.insecureWriteRequestsAfterFormSubmit = 1;
      if (candidate.isThirdParty) counters.thirdPartyWriteRequestsAfterFormSubmit = 1;
      counters.sensitiveWriteRequestsAfterFormSubmit = 1;
      if (candidate.isInsecure) {
        counters.insecureSensitiveWriteRequests = 1;
        timeline.push({ type: "UNENCRYPTED_SENSITIVE_WRITE" });
      }
      if (candidate.isUnknownWrite) {
        counters.crossDomainSensitiveWriteRequests = 1;
        destination = true;
        timeline.push({ type: "CROSS_DOMAIN_SENSITIVE_WRITE" });
      }
    }
    if (candidate.isUnknownBeacon) {
      counters.beaconOrPingAfterSensitiveInput = 1;
      destination = true;
      timeline.push({ type: "BEACON_AFTER_SENSITIVE_INPUT" });
    }
    if (candidate.isQueryImage && trigger === "FORM_SUBMIT") {
      counters.queryBearingGetAfterSensitiveForm = 1;
      destination = true;
      timeline.push({ type: "QUERY_GET_AFTER_SENSITIVE_FORM", roleOverride: "UNKNOWN_BEACON" });
    }
    return { accept: true, counters, destination, timeline };
  }

  return { SENSITIVE_REQUEST_WINDOW_MS, isUnknownBeaconDestination, isCandidateRelevant, correlationEffects };
});
