(function exposeArgusReputation(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusReputation = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createReputation() {
  "use strict";

  // Verdicts are cached per-domain in chrome.storage so we don't query on every
  // visit. Blocklist state changes slowly; 6h keeps it fresh without noise.
  const REPUTATION_TTL_MS = 6 * 60 * 60 * 1000;

  function normalizeDomain(domain) {
    return String(domain || "").trim().toLowerCase().replace(/\.+$/, "");
  }

  function cacheKey(domain) {
    return `rep:${normalizeDomain(domain)}`;
  }

  function isFresh(entry, now, ttl) {
    const at = entry && Number(entry.checkedAt);
    return Boolean(entry) && Number.isFinite(at) && (Number(now) - at) < (Number(ttl) || REPUTATION_TTL_MS);
  }

  // Reputation is only worth querying for untrusted, real public hostnames. Skip
  // trusted domains, blanks, loopback/IP hosts, and local files.
  function shouldQuery(domain, isTrusted) {
    const host = normalizeDomain(domain);
    if (!host || isTrusted) return false;
    if (host === "localhost" || host === "local-file") return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":")) return false;
    return host.includes(".");
  }

  // Parse a backend /v1/reputation/check response into a normalized verdict. A
  // positive listing is either `listed: true` or `verdict: "malicious"`; anything
  // else (unknown / not-listed / malformed) is treated as not-listed.
  function verdictFromResponse(json) {
    const raw = json && typeof json === "object" ? json : {};
    const listed = raw.listed === true || String(raw.verdict || "").toLowerCase() === "malicious";
    return {
      available: true,
      listed,
      source: listed ? String(raw.source || "REPUTATION_FEED").slice(0, 40) : "NONE",
      matchedDomain: listed ? String(raw.matchedDomain || raw.host || raw.domain || "").slice(0, 180) : "",
      checkedAt: Date.now()
    };
  }

  function unavailableVerdict() {
    return { available: false, listed: false, source: "NONE", matchedDomain: "", checkedAt: Date.now() };
  }

  // The shape the evidence policy consumes on context.reputation.
  function toPolicyContext(verdict) {
    const v = verdict || {};
    return { listed: Boolean(v.listed), source: v.source || "NONE", matchedDomain: v.matchedDomain || "" };
  }

  return {
    REPUTATION_TTL_MS, normalizeDomain, cacheKey, isFresh, shouldQuery,
    verdictFromResponse, unavailableVerdict, toPolicyContext
  };
});
