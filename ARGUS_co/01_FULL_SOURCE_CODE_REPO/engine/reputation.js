(function exposeArgusReputation(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusReputation = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createReputation() {
  "use strict";

  // Verdicts are cached per-domain in chrome.storage so we don't query on every
  // visit. Blocklist state changes slowly; 6h keeps MALICIOUS fresh without noise.
  // Graded verdicts are softer signals and get shorter lifetimes so a host can be
  // re-evaluated sooner.
  const REPUTATION_TTL_MS = 6 * 60 * 60 * 1000;
  const TTL_BY_VERDICT_MS = Object.freeze({
    MALICIOUS: REPUTATION_TTL_MS,
    RISKY_CONTEXT: 60 * 60 * 1000,
    TRUSTED: 30 * 60 * 1000,
    UNKNOWN: 30 * 60 * 1000
  });

  const VERDICTS = Object.freeze(["UNKNOWN", "TRUSTED", "RISKY_CONTEXT", "MALICIOUS"]);

  function normalizeDomain(domain) {
    return String(domain || "").trim().toLowerCase().replace(/\.+$/, "");
  }

  function cacheKey(domain) {
    return `rep:${normalizeDomain(domain)}`;
  }

  function normalizeVerdictName(value) {
    const name = String(value || "UNKNOWN").toUpperCase();
    // The codex backend briefly used RISKY_CATEGORY; treat it as RISKY_CONTEXT.
    if (name === "RISKY_CATEGORY") return "RISKY_CONTEXT";
    return VERDICTS.includes(name) ? name : "UNKNOWN";
  }

  function ttlForVerdict(verdict) {
    return TTL_BY_VERDICT_MS[normalizeVerdictName(verdict)] || TTL_BY_VERDICT_MS.UNKNOWN;
  }

  function isFresh(entry, now, ttl) {
    const at = entry && Number(entry.checkedAt);
    const effectiveTtl = Number(ttl) || ttlForVerdict(entry && entry.verdict);
    return Boolean(entry) && Number.isFinite(at) && (Number(now) - at) < effectiveTtl;
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

  // Parse a backend /v1/reputation/check response into a normalized graded verdict:
  // UNKNOWN | TRUSTED | RISKY_CONTEXT | MALICIOUS. `listed` is kept as the
  // MALICIOUS-equivalent boolean for backward compatibility: either `listed: true`
  // or a malicious verdict string counts.
  function verdictFromResponse(json) {
    const raw = json && typeof json === "object" ? json : {};
    const listed = raw.listed === true || String(raw.verdict || "").toUpperCase() === "MALICIOUS";
    const verdict = listed ? "MALICIOUS" : normalizeVerdictName(raw.verdict);
    return {
      available: true,
      listed,
      verdict,
      confidence: String(raw.confidence || (listed ? "HIGH" : "LOW")).slice(0, 12).toUpperCase(),
      source: verdict !== "UNKNOWN" ? String(raw.source || (Array.isArray(raw.sources) && raw.sources[0]) || "REPUTATION_FEED").slice(0, 40) : "NONE",
      sources: Array.isArray(raw.sources) ? raw.sources.slice(0, 5).map((item) => String(item).slice(0, 40)) : [],
      categories: Array.isArray(raw.categories) ? raw.categories.slice(0, 5).map((item) => String(item).slice(0, 40)) : [],
      matchedDomain: verdict !== "UNKNOWN" ? String(raw.matchedDomain || raw.hostname || raw.host || raw.domain || "").slice(0, 180) : "",
      checkedAt: Date.now()
    };
  }

  function unavailableVerdict() {
    return {
      available: false, listed: false, verdict: "UNKNOWN", confidence: "LOW",
      source: "NONE", sources: [], categories: [], matchedDomain: "", checkedAt: Date.now()
    };
  }

  // The shape the evidence policy consumes on context.reputation.
  function toPolicyContext(verdict) {
    const v = verdict || {};
    return {
      listed: Boolean(v.listed),
      verdict: normalizeVerdictName(v.verdict || (v.listed ? "MALICIOUS" : "UNKNOWN")),
      confidence: String(v.confidence || "LOW"),
      source: v.source || "NONE",
      categories: Array.isArray(v.categories) ? v.categories.slice(0, 5) : [],
      matchedDomain: v.matchedDomain || ""
    };
  }

  return {
    REPUTATION_TTL_MS, TTL_BY_VERDICT_MS, VERDICTS,
    normalizeDomain, cacheKey, isFresh, shouldQuery, ttlForVerdict, normalizeVerdictName,
    verdictFromResponse, unavailableVerdict, toPolicyContext
  };
});
