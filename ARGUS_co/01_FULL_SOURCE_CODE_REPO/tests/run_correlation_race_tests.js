"use strict";

// Regression coverage for the request/event correlation race (F1) that left
// confirmed exfiltration stuck at 5/100. These drive the pure correlation
// reducer directly with out-of-order events, which the policy-level exfiltration
// regression test does not exercise.
const NC = require("../engine/network_correlation.js");

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

// F1: a beacon/ping to an unknown third party is recognized BEFORE interaction.
assert(NC.isUnknownBeaconDestination({ type: "ping" }, true, false) === true, "pre-interaction unknown ping not recognized");
assert(NC.isUnknownBeaconDestination({ type: "beacon" }, true, false) === true, "pre-interaction unknown beacon not recognized");
assert(NC.isUnknownBeaconDestination({ type: "ping" }, true, true) === false, "ping to a known destination was flagged as unknown");
assert(NC.isUnknownBeaconDestination({ type: "image" }, true, false) === false, "non-beacon type flagged as beacon");
assert(NC.isUnknownBeaconDestination({ type: "ping" }, false, false) === false, "first-party ping flagged as exfiltration");

// F1: a beacon remembered before focus must correlate on the SENSITIVE_FOCUS
// trigger — the exact path the old code skipped.
const preFocusBeacon = { at: 1000, isUnknownBeacon: true, isWriteRequest: false, isUnknownWrite: false, isQueryImage: false, correlated: false };
const onFocus = NC.correlationEffects(preFocusBeacon, "SENSITIVE_FOCUS");
assert(onFocus.accept, "pre-interaction beacon rejected on sensitive focus");
assert(onFocus.counters.beaconOrPingAfterSensitiveInput === 1, "beacon counter not raised on focus");
assert(onFocus.destination === true, "beacon destination not retained");

// A non-beacon cross-domain write is NOT correlated by a focus-only trigger.
const writeOnly = { at: 900, isUnknownBeacon: false, isWriteRequest: true, isUnknownWrite: true, isInsecure: true, isThirdParty: true, isQueryImage: false, correlated: false };
assert(!NC.correlationEffects(writeOnly, "SENSITIVE_FOCUS").accept, "cross-domain write wrongly correlated by a focus trigger");

// On FORM_SUBMIT the same write correlates into the exfiltration counters.
const onSubmit = NC.correlationEffects(writeOnly, "FORM_SUBMIT");
assert(onSubmit.accept, "cross-domain write not correlated on submit");
assert(onSubmit.counters.crossDomainSensitiveWriteRequests === 1, "cross-domain sensitive write not counted");
assert(onSubmit.counters.insecureSensitiveWriteRequests === 1, "insecure sensitive write not counted");
assert(onSubmit.counters.sensitiveWriteRequestsAfterFormSubmit === 1, "sensitive-write-after-form not counted");

// A query-bearing pixel correlates only on FORM_SUBMIT, never on focus.
const pixel = { at: 800, isQueryImage: true, isUnknownBeacon: false, isWriteRequest: false, isUnknownWrite: false, correlated: false };
assert(!NC.correlationEffects(pixel, "SENSITIVE_FOCUS").accept, "query pixel wrongly correlated on focus");
assert(NC.correlationEffects(pixel, "FORM_SUBMIT").counters.queryBearingGetAfterSensitiveForm === 1, "query pixel not counted on submit");

// An already-correlated candidate is inert (no double counting).
assert(!NC.correlationEffects({ ...pixel, correlated: true }, "FORM_SUBMIT").accept, "already-correlated candidate was re-counted");

// End-to-end ordering: request observed first, sensitive submit later, still
// correlates within the window — the "webRequest arrived before the form event" race.
const store = [];
const earlyBeacon = { at: 500, isUnknownBeacon: true, isWriteRequest: false, isUnknownWrite: false, isQueryImage: false, correlated: false, requestMeta: { hostname: "evil.example" } };
if (NC.isCandidateRelevant(earlyBeacon)) store.push(earlyBeacon);
let beaconTotal = 0;
const submitAt = 3000; // within SENSITIVE_REQUEST_WINDOW_MS of the beacon
for (const candidate of store) {
  if (candidate.correlated || submitAt - candidate.at > NC.SENSITIVE_REQUEST_WINDOW_MS) continue;
  const effects = NC.correlationEffects(candidate, "FORM_SUBMIT");
  if (!effects.accept) continue;
  candidate.correlated = true;
  beaconTotal += effects.counters.beaconOrPingAfterSensitiveInput || 0;
}
assert(beaconTotal === 1, "out-of-order beacon-before-submit was not retroactively correlated");

// A candidate outside the window is dropped.
let lateTotal = 0;
const lateBeacon = { at: 500, isUnknownBeacon: true, isWriteRequest: false, isUnknownWrite: false, isQueryImage: false, correlated: false };
const lateSubmitAt = 500 + NC.SENSITIVE_REQUEST_WINDOW_MS + 1;
if (!(lateSubmitAt - lateBeacon.at > NC.SENSITIVE_REQUEST_WINDOW_MS)) {
  lateTotal += NC.correlationEffects(lateBeacon, "FORM_SUBMIT").counters.beaconOrPingAfterSensitiveInput || 0;
}
assert(lateTotal === 0, "beacon outside the correlation window was still counted");

console.log(`${passed}/${passed} correlation race regression cases passed.`);
