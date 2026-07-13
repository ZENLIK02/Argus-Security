(function exposeArgusReputationClient(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusReputationClient = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createReputationClient() {
  "use strict";

  // Orchestrates the P1 reputation lookup. All side effects are injected via `deps`
  // so the exact client logic can be exercised end-to-end against a real backend in
  // tests, without Chrome. The service worker wires chrome.* into `deps`.
  //
  // deps = {
  //   storageGet(keys) -> Promise<object>,
  //   storageSet(obj)  -> Promise<void>,
  //   fetchImpl(url, opts) -> Promise<Response>,
  //   getNavigationId(tabId) -> string,
  //   scheduleRescan(tabId, scanPhase) -> void,   // triggers a fresh page scan
  //   inFlight: Set,                              // de-dupes concurrent lookups
  //   now() -> number,                            // optional, defaults Date.now
  //   log(diag) -> void                           // optional, defaults no-op
  // }

  const Reputation = typeof ArgusReputation !== "undefined"
    ? ArgusReputation
    : (typeof module === "object" && module.exports ? require("./reputation.js") : null);

  const REQUEST_TIMEOUT_MS = 1500;

  function nowOf(deps) { return (deps && typeof deps.now === "function") ? deps.now() : Date.now(); }
  function logOf(deps, diag) { if (deps && typeof deps.log === "function") deps.log(diag); }

  async function getCached(domain, deps) {
    try {
      const key = Reputation.cacheKey(domain);
      const stored = await deps.storageGet([key]);
      const entry = stored && stored[key];
      // TTL depends on the cached verdict (MALICIOUS 6h, RISKY_CONTEXT 1h, else 30min).
      return Reputation.isFresh(entry, nowOf(deps)) ? entry : null;
    } catch (error) {
      return null;
    }
  }

  // Returns { context, diag }. context is the policy-context object for a fresh
  // cached verdict (or undefined). On a cache miss, kicks off a background refresh.
  async function resolve(signals, settings, tabId, deps) {
    const diag = {
      enabled: Boolean(settings.reputationEnabled),
      endpoint: settings.reputationEndpoint,
      domain: signals.domain,
      queried: false, cache: "n/a", listed: false, verdict: "UNKNOWN", source: "NONE", applied: false, reason: ""
    };
    if (!settings.reputationEnabled || !Reputation) {
      diag.reason = settings.reputationEnabled ? "module_unavailable" : "disabled";
      return { context: undefined, diag };
    }
    if (!Reputation.shouldQuery(signals.domain, signals.isTrustedDomain)) {
      diag.reason = signals.isTrustedDomain ? "trusted_domain" : "not_queryable";
      return { context: undefined, diag };
    }
    diag.queried = true;
    const cached = await getCached(signals.domain, deps);
    if (cached) {
      diag.cache = "hit";
      diag.available = Boolean(cached.available);
      diag.listed = Boolean(cached.listed);
      diag.verdict = Reputation.normalizeVerdictName(cached.verdict || (cached.listed ? "MALICIOUS" : "UNKNOWN"));
      diag.source = cached.source || "NONE";
      diag.applied = Boolean(cached.available && (cached.listed || diag.verdict !== "UNKNOWN"));
      return { context: cached.available ? Reputation.toPolicyContext(cached) : undefined, diag };
    }
    diag.cache = "miss";
    diag.reason = "fetching";
    Promise.resolve(refresh(signals.domain, tabId, settings, deps)).catch(() => undefined);
    return { context: undefined, diag };
  }

  // Fetches the verdict, caches it, and (for a malicious verdict) triggers a prompt
  // final rescan so it is applied immediately and cannot be overwritten by a stale
  // lower-phase SAFE scan. Awaitable for tests.
  async function refresh(domain, tabId, settings, deps) {
    const host = Reputation.normalizeDomain(domain);
    if (!host) return { skipped: "empty_host" };
    if (deps.inFlight && deps.inFlight.has(host)) return { skipped: "in_flight" };
    if (deps.inFlight) deps.inFlight.add(host);
    const scheduledNavigationId = deps.getNavigationId ? deps.getNavigationId(tabId) : null;
    const diag = { host, endpoint: settings.reputationEndpoint, at: new Date().toISOString(), httpStatus: null, verdict: null, error: null };
    let verdict;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      const response = await deps.fetchImpl(settings.reputationEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Hostname only (metadata). No URL path, query, cookies, or user data.
        // `hostname` is canonical; `host` kept for pre-merge backend compatibility.
        body: JSON.stringify({ hostname: host, host }),
        credentials: "omit",
        signal: controller.signal
      });
      clearTimeout(timer);
      diag.httpStatus = response.status;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      verdict = Reputation.verdictFromResponse(await response.json());
      diag.verdict = verdict.verdict;
    } catch (error) {
      verdict = Reputation.unavailableVerdict();
      diag.error = String(error && error.message || error).slice(0, 200);
    } finally {
      if (deps.inFlight) deps.inFlight.delete(host);
    }
    diag.available = Boolean(verdict.available);
    diag.listed = Boolean(verdict.listed);
    logOf(deps, diag);
    try { await deps.storageSet({ lastReputationDiag: diag }); } catch (error) { /* ignore */ }

    // Do NOT cache "unavailable" (backend offline) so it retries on the next visit.
    if (!verdict.available) return { verdict, diag };
    try {
      await deps.storageSet({ [Reputation.cacheKey(host)]: verdict });
    } catch (error) {
      return { verdict, diag, cached: false };
    }
    let rescanScheduled = false;
    if (verdict.listed && Number.isInteger(tabId) && tabId >= 0 &&
      (!deps.getNavigationId || deps.getNavigationId(tabId) === scheduledNavigationId)) {
      if (deps.scheduleRescan) deps.scheduleRescan(tabId, "INTERACTION_FINAL");
      rescanScheduled = true;
    }
    return { verdict, diag, cached: true, rescanScheduled };
  }

  return { resolve, refresh, getCached, REQUEST_TIMEOUT_MS };
});
