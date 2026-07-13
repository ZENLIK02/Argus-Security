(function exposeArgusScanFreshness(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusScanFreshness = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createScanFreshness() {
  "use strict";

  // Scan phases in increasing completeness. INTERACTION_FINAL is the richest
  // (post-interaction network evidence); PRELIMINARY is the earliest/weakest.
  function scanPhaseRank(phase) {
    switch (String(phase || "").toUpperCase()) {
      case "INTERACTION_FINAL": return 3;
      case "FINAL": return 2;
      case "PRELIMINARY": return 1;
      default: return 0;
    }
  }

  // Monotonic write guard: a stored scan must never be overwritten by a
  // lower-completeness or older scan for the SAME page load. A late-resolving
  // PRELIMINARY therefore cannot clobber a finished INTERACTION_FINAL. A genuinely
  // new page (different navigationId / pageKey) always replaces — cross-page stale
  // scans are already filtered by the epoch/pageKey guards before this point.
  function shouldReplaceStoredScan(existing, incoming) {
    if (!existing) return true;
    if (!incoming) return false;
    const samePage = existing.navigationId && incoming.navigationId
      ? existing.navigationId === incoming.navigationId
      : String(existing.pageKey || "") === String(incoming.pageKey || "");
    if (!samePage) return true;
    const rankNew = scanPhaseRank(incoming.scanPhase);
    const rankOld = scanPhaseRank(existing.scanPhase);
    if (rankNew !== rankOld) return rankNew > rankOld; // higher phase wins; never downgrade
    const tNew = Date.parse(incoming.timestamp || "") || 0;
    const tOld = Date.parse(existing.timestamp || "") || 0;
    return tNew >= tOld; // same phase: keep the newer read
  }

  // FNV-1a — identical to content.js routeFingerprint so page identities match.
  function routeFingerprint(value) {
    let hash = 2166136261;
    for (const character of String(value || "")) {
      hash ^= character.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  // Mirrors content.js getPageKey: origin + pathname + fingerprint(search#hash),
  // so SPA hash/query routes produce distinct page identities.
  function pageKeyFor(url) {
    try {
      const parsed = typeof url === "string" ? new URL(url) : url;
      return `${parsed.origin}${parsed.pathname}#${routeFingerprint(`${parsed.search}${parsed.hash}`)}`;
    } catch (error) {
      return "";
    }
  }

  // True when a stored scan belongs to the tab's current page. Prefers the exact
  // SPA-route identity (pageKey) and falls back to origin+pathname.
  function scanMatchesTab(scan, tabUrl) {
    if (!scan) return false;
    if (!tabUrl) return true;
    try {
      const activeUrl = new URL(tabUrl);
      if (scan.pageKey) {
        return String(scan.pageKey) === pageKeyFor(activeUrl);
      }
      const scanUrl = new URL(scan.url || "");
      return activeUrl.origin === scanUrl.origin && activeUrl.pathname === scanUrl.pathname;
    } catch (error) {
      return false;
    }
  }

  return { scanPhaseRank, shouldReplaceStoredScan, routeFingerprint, pageKeyFor, scanMatchesTab };
});
