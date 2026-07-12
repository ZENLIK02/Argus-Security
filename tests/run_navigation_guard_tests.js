"use strict";
const Guard = require("../engine/navigation_session_guard.js");
let clock = 1000;
const guard = Guard.create(() => ++clock);

const risky = guard.begin(1, "https://risk.test/", 1);
const safe = guard.begin(1, "https://safe.test/", 2);
assert(!guard.matches({ tabId: 1, navigationId: risky.navigationId }), "safe page accepted old high-risk event");
assert(guard.matches({ tabId: 1, navigationId: safe.navigationId }), "safe page rejected current event");

const rapidA = guard.begin(2, "https://a.test/", 1);
const rapidB = guard.begin(2, "https://b.test/", 2);
assert(!guard.matches({ tabId: 2, navigationId: rapidA.navigationId }), "rapid navigation accepted stale event");
assert(guard.matches({ tabId: 2, navigationId: rapidB.navigationId }), "rapid navigation rejected latest event");

const back = guard.begin(3, "https://back.test/", 3);
assert(guard.matches({ tabId: 3, pageKey: back.pageKey }), "back/forward current page key rejected");
assert(!guard.matches({ tabId: 3, pageKey: "https://forward.test/" }), "back/forward stale page key accepted");

const iframe = guard.begin(4, "https://host.test/", 1);
assert(guard.matches({ tabId: 4, navigationId: iframe.navigationId, frameId: 9 }), "iframe reload lost current navigation identity");

guard.begin(5, "https://first.test/", 1);
guard.clear(5);
const reused = guard.begin(5, "https://reused.test/", 1);
assert(guard.matches({ tabId: 5, navigationId: reused.navigationId }), "tab reuse rejected new session");

const delayed = guard.begin(6, "https://old.test/", 1);
guard.begin(6, "https://new.test/", 2);
assert(!guard.matches({ tabId: 6, navigationId: delayed.navigationId }), "delayed service-worker message was accepted");

const cleared = guard.begin(7, "https://clear.test/", 1);
guard.clear(7);
assert(!guard.matches({ tabId: 7, navigationId: cleared.navigationId }), "old event survived state clear");

// F2: a navigationId re-issued for the SAME page identity must still authorize a
// sensitive event (content script briefly holds a stale id after re-session).
const sess1 = guard.begin(8, "https://spa.test/app", 1);
guard.begin(8, "https://spa.test/app", 2);
assert(guard.matches({ tabId: 8, pageKey: "https://spa.test/app", navigationId: sess1.navigationId }), "same-page re-session rejected a valid stale navigationId");
assert(!guard.matches({ tabId: 8, pageKey: "https://other.test/app" }), "different page key accepted despite same tab");

// F2: note() adopts a pageKey onto a session begun without one (full navigation),
// so a subsequent event is authorized by page identity even with a stale id.
guard.begin(9, "", 1);
guard.note(9, "https://full.test/home");
assert(guard.matches({ tabId: 9, pageKey: "https://full.test/home", navigationId: "stale-xyz" }), "note() pageKey did not authorize a same-page event");
assert(!guard.matches({ tabId: 9, pageKey: "https://full.test/other" }), "note() pageKey accepted a different page");

console.log("11/11 navigation session isolation cases passed.");

function assert(condition, message) { if (!condition) { console.error(`FAIL ${message}`); process.exit(1); } }
