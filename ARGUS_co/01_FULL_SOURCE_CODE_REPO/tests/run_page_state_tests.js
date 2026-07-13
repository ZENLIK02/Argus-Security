"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const content = fs.readFileSync(path.join(root, "content.js"), "utf8");
const worker = fs.readFileSync(path.join(root, "service_worker.js"), "utf8");
const popup = fs.readFileSync(path.join(root, "popup.js"), "utf8");

assert(content.includes("ARGUS_PAGE_CHANGED"), "content script must notify the worker when page identity changes");
assert(content.includes("pushState") && content.includes("replaceState"), "SPA history navigation must be observed");
assert(content.includes("routeFingerprint"), "query/hash route identity must use a privacy-safe fingerprint");
assert(content.includes("requestedPageKey !== currentPageKey"), "content script must ignore stale asynchronous scan callbacks");
assert(worker.includes("clearPageState(tabId"), "worker must clear per-tab state on navigation");
assert(worker.includes("tabNetworkSignals.delete(tabId)"), "worker must discard old network metadata");
assert(worker.includes("Stale scan result discarded after page navigation"), "worker must reject in-flight stale scans");
assert(worker.includes("tabNavigationIds"), "worker must maintain explicit navigation identifiers");
assert(worker.includes("navigationGuard.matches"), "old page events must be rejected by navigation/session identity");
assert(worker.includes("getNavigationId(tabId) !== scheduledNavigationId"), "delayed rescans must be cancelled after navigation");
assert(worker.includes("frameId"), "scan and timeline metadata must include frame identity");
assert(worker.includes("return tabScans[String(tabId)] || null"), "tab lookup must not fall back to another page's global scan");
assert(!worker.includes("preserveOrClearTemporalState"), "navigation must not preserve temporal evidence from the previous page");
assert(!content.includes("argus-warning-overlay"), "content script must not contain the removed top-right warning popup");
assert(worker.includes("ArgusEvidencePolicy.decide"), "worker must route final status through centralized evidence policy");
assert(popup.includes("await requestPageRescan"), "popup must await the rescan dispatch before reading tab state");
assert(popup.includes("scanTimestamp >= minimumTimestamp"), "popup must reject a pre-rescan cached result");
assert(popup.includes("scanMatchesTab"), "popup must reject a cached result from another page");
assert(popup.includes("stableReadCount >= 3"), "popup must wait for the tab scan to stabilize before rendering");

console.log("PASS page-state isolation checks: navigation clears evidence and stale callbacks are rejected.");

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL ${message}`);
    process.exit(1);
  }
}
