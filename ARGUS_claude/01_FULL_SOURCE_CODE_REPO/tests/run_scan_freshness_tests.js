"use strict";

// Regression coverage for stored-scan freshness (F10) and popup route matching
// (F11): a late/lower-completeness scan must not clobber a better one, and SPA
// hash/query routes must resolve to distinct page identities.
const F = require("../engine/scan_freshness.js");

let passed = 0;
function assert(condition, message) {
  if (!condition) { console.error(`FAIL ${message}`); process.exit(1); }
  passed += 1;
}

// Phase ranking.
assert(F.scanPhaseRank("INTERACTION_FINAL") > F.scanPhaseRank("FINAL"), "INTERACTION_FINAL should outrank FINAL");
assert(F.scanPhaseRank("FINAL") > F.scanPhaseRank("PRELIMINARY"), "FINAL should outrank PRELIMINARY");
assert(F.scanPhaseRank("nonsense") === 0, "unknown phase should rank 0");

const nav = "nav-1";
const finalScan = { navigationId: nav, pageKey: "https://a.test/p#0", scanPhase: "INTERACTION_FINAL", timestamp: "2026-07-12T10:00:05.000Z" };
const prelim = { navigationId: nav, pageKey: "https://a.test/p#0", scanPhase: "PRELIMINARY", timestamp: "2026-07-12T10:00:06.000Z" };

// F10 core: a late PRELIMINARY (even with a newer timestamp) must NOT overwrite a
// finished INTERACTION_FINAL for the same page.
assert(F.shouldReplaceStoredScan(finalScan, prelim) === false, "late preliminary clobbered the interaction-final scan");
// Higher phase always replaces a lower one.
assert(F.shouldReplaceStoredScan(prelim, finalScan) === true, "interaction-final failed to replace a preliminary");
// No existing scan → always store.
assert(F.shouldReplaceStoredScan(null, prelim) === true, "first scan for a page was rejected");

// Same phase: newer timestamp wins, older is rejected.
const finalNewer = { ...finalScan, timestamp: "2026-07-12T10:00:09.000Z" };
assert(F.shouldReplaceStoredScan(finalScan, finalNewer) === true, "newer same-phase scan was rejected");
assert(F.shouldReplaceStoredScan(finalNewer, finalScan) === false, "older same-phase scan overwrote a newer one");

// A different page load always replaces (new navigationId, or new pageKey).
const otherNav = { navigationId: "nav-2", pageKey: "https://a.test/p#0", scanPhase: "PRELIMINARY", timestamp: "2026-07-12T10:00:01.000Z" };
assert(F.shouldReplaceStoredScan(finalScan, otherNav) === true, "new navigation failed to replace the previous page's scan");
const noNavA = { pageKey: "https://a.test/x#0", scanPhase: "FINAL", timestamp: "2026-07-12T10:00:05.000Z" };
const noNavB = { pageKey: "https://a.test/y#0", scanPhase: "PRELIMINARY", timestamp: "2026-07-12T10:00:01.000Z" };
assert(F.shouldReplaceStoredScan(noNavA, noNavB) === true, "different pageKey (no navId) failed to replace");

// F11 core: SPA hash routes produce distinct page identities.
const routeSettings = F.pageKeyFor("https://app.test/dash#/settings");
const routeProfile = F.pageKeyFor("https://app.test/dash#/profile");
assert(routeSettings !== routeProfile, "distinct SPA hash routes produced the same pageKey");
assert(F.pageKeyFor("https://app.test/dash#/settings") === routeSettings, "pageKey is not stable for the same route");

// scanMatchesTab: exact route match via pageKey.
const spaScan = { pageKey: routeSettings, url: "https://app.test/dash" };
assert(F.scanMatchesTab(spaScan, "https://app.test/dash#/settings") === true, "matching SPA route was not recognized");
assert(F.scanMatchesTab(spaScan, "https://app.test/dash#/profile") === false, "a different SPA route was wrongly matched");

// Fallback to origin+pathname when no pageKey is present.
const legacyScan = { url: "https://site.test/page" };
assert(F.scanMatchesTab(legacyScan, "https://site.test/page?q=1") === true, "origin+pathname fallback failed to match");
assert(F.scanMatchesTab(legacyScan, "https://site.test/other") === false, "origin+pathname fallback matched a different path");

console.log(`${passed}/${passed} scan freshness regression cases passed.`);
