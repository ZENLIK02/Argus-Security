(function exposeArgusFeedbackEndpoint(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusFeedbackEndpoint = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createFeedbackEndpoint() {
  "use strict";

  // The false-positive collector is a LOCAL developer server. Only loopback hosts
  // are permitted so a settings change (or a tampered stored setting) can never
  // point reports — which include page domain + evidence + feature vector — at an
  // arbitrary external endpoint (F16). One source of truth for the worker and the
  // options page.
  function isLoopbackHost(hostname) {
    const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
    return host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host);
  }

  function normalizeFeedbackEndpoint(value, fallback) {
    const safeFallback = String(fallback || "http://localhost:8000/feedback/false-positive");
    try {
      const url = new URL(String(value || safeFallback));
      if (!["http:", "https:"].includes(url.protocol)) return safeFallback;
      return isLoopbackHost(url.hostname) ? url.href : safeFallback;
    } catch (error) {
      return safeFallback;
    }
  }

  return { isLoopbackHost, normalizeFeedbackEndpoint };
});
