(function exposeArgusNavigationGuard(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusNavigationGuard = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createNavigationGuardApi() {
  "use strict";
  function create(now = () => Date.now()) {
    const sessions = new Map();
    let sequence = 0;
    function begin(tabId, pageKey, epoch = 0) {
      sequence += 1;
      const session = { tabId, pageKey: String(pageKey || ""), epoch, navigationId: `nav-${tabId}-${epoch}-${now().toString(36)}-${sequence}`, startedAt: now() };
      sessions.set(tabId, session);
      return session;
    }
    function ensure(tabId, pageKey = "", epoch = 0) { return sessions.get(tabId) || begin(tabId, pageKey, epoch); }
    function current(tabId) { return sessions.get(tabId) || null; }
    // Adopt a page identity onto a session that was begun without one (e.g. a
    // full navigation cleared via tabs.onUpdated). Lets later page events be
    // authorized by pageKey once it becomes known.
    function note(tabId, pageKey) {
      const session = sessions.get(tabId);
      if (session && pageKey && !session.pageKey) session.pageKey = String(pageKey);
    }
    function matches(message) {
      const session = sessions.get(message.tabId);
      if (!session) return false;
      const pageKey = message.pageKey ? String(message.pageKey) : "";
      // Page identity is authoritative. A navigationId re-issued for the SAME
      // page (rapid re-session, content script holding a slightly stale id) must
      // not reject a legitimate sensitive event; a changed pageKey still does.
      if (pageKey && session.pageKey) {
        return pageKey === session.pageKey;
      }
      // Fall back to navigationId when a pageKey is not available on either side.
      if (message.navigationId && message.navigationId !== session.navigationId) return false;
      return true;
    }
    function clear(tabId) { sessions.delete(tabId); }
    return { begin, ensure, current, note, matches, clear };
  }
  return { create };
});
