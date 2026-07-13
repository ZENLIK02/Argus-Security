(function exposeArgusDomainSimilarity(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusDomainSimilarity = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createDomainSimilarity() {
  "use strict";

  // Offline brand-lookalike / homoglyph / typosquat detector. Pure and local — no
  // network. Catches fresh (unlisted) impersonation that reputation feeds miss.

  // Single-character confusables: leetspeak digits/symbols + common Cyrillic/Greek
  // homoglyphs mapped to their Latin look-alike. Enough to canonicalize the vast
  // majority of real homoglyph phishing without a full Unicode table.
  const CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l", "£": "l",
    // Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
    "і": "i", "ѕ": "s", "ԁ": "d", "ј": "j", "ԛ": "q", "ɡ": "g",
    // Greek
    "ο": "o", "α": "a", "ρ": "p", "ν": "v", "ι": "i", "κ": "k",
    "ε": "e", "Α": "a", "Ο": "o", "Ρ": "p"
  };

  const DEFAULT_SUFFIXES = new Set([
    "co.th", "or.th", "go.th", "ac.th", "in.th", "co.uk", "org.uk", "ac.uk", "com.au",
    "co.jp", "co.kr", "com.sg", "com.my", "co.nz", "com.br"
  ]);

  function normalizeHost(value) {
    return String(value || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  }

  // Canonical "skeleton": strip diacritics, fold visual multi-char shapes and
  // single-char confusables, keep alphanumerics only. Two strings with the same
  // skeleton look alike to a human.
  function skeleton(input) {
    let s = String(input || "").toLowerCase();
    try { s = s.normalize("NFKD"); } catch (error) { /* environments without NFKD */ }
    s = s.replace(/[̀-ͯ]/g, "");
    s = s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");
    let out = "";
    for (const ch of s) out += Object.prototype.hasOwnProperty.call(CONFUSABLES, ch) ? CONFUSABLES[ch] : ch;
    return out.replace(/[^a-z0-9]/g, "");
  }

  function registrableDomain(host, suffixSet) {
    const labels = normalizeHost(host).split(".").filter(Boolean);
    if (labels.length <= 2) return labels.join(".");
    const twoLabelSuffix = labels.slice(-2).join(".");
    return (suffixSet && suffixSet.has(twoLabelSuffix) ? labels.slice(-3) : labels.slice(-2)).join(".");
  }

  function primaryLabel(registrable) {
    return String(registrable || "").split(".")[0] || "";
  }

  function hostTokens(host) {
    return normalizeHost(host).split(/[.\-]/).filter(Boolean);
  }

  function editDistance(a, b) {
    const s = String(a || "");
    const t = String(b || "");
    if (s === t) return 0;
    if (!s.length) return t.length;
    if (!t.length) return s.length;
    let prev = Array.from({ length: t.length + 1 }, (_, i) => i);
    for (let i = 1; i <= s.length; i += 1) {
      const curr = [i];
      for (let j = 1; j <= t.length; j += 1) {
        const cost = s[i - 1] === t[j - 1] ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = curr;
    }
    return prev[t.length];
  }

  function none() {
    return { match: false, kind: "NONE", brand: "", brandToken: "", token: "", distance: null, confidence: 0 };
  }

  // Analyze `host` against a list of brand registrable domains. Returns the best
  // (highest-precision) lookalike finding, or a no-match.
  function analyze(host, brands, options) {
    const h = normalizeHost(host);
    if (!h || !h.includes(".") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return none();
    const suffixSet = new Set((options && options.multiLabelSuffixes) || DEFAULT_SUFFIXES);
    const reg = registrableDomain(h, suffixSet);
    const token = primaryLabel(reg);
    if (token.length < 3) return none();
    const skelToken = skeleton(token);
    const tokens = hostTokens(h);
    let best = none();

    for (const brandDomain of (brands || [])) {
      const b = normalizeHost(brandDomain);
      if (!b) continue;
      // The brand itself or any of its subdomains is never a lookalike of itself.
      if (h === b || h.endsWith("." + b) || reg === b) continue;
      const brandReg = registrableDomain(b, suffixSet);
      const brandToken = primaryLabel(brandReg);
      if (brandToken.length < 3) continue;
      const skelBrand = skeleton(brandToken);

      // HOMOGLYPH: visually identical token, but different underlying characters.
      if (skelToken === skelBrand && token !== brandToken) {
        return { match: true, kind: "HOMOGLYPH", brand: b, brandToken, token, distance: 0, confidence: 0.97 };
      }

      if (brandToken.length >= 4) {
        // TYPOSQUAT: a small edit distance on the visual skeletons.
        const dist = editDistance(skelToken, skelBrand);
        const maxDist = brandToken.length >= 8 ? 2 : 1;
        if (dist >= 1 && dist <= maxDist && Math.abs(token.length - brandToken.length) <= maxDist) {
          const confidence = dist === 1 ? 0.85 : 0.75;
          if (confidence > best.confidence) best = { match: true, kind: "TYPOSQUAT", brand: b, brandToken, token, distance: dist, confidence };
          continue;
        }
        // COMBOSQUAT: the brand name appears as a whole host token on an unrelated
        // registrable domain (e.g. paypal.login-secure.tk). Lower precision — the
        // engine only acts on this when the page also collects credentials.
        if (tokens.includes(brandToken) && reg !== brandReg && best.confidence < 0.6) {
          best = { match: true, kind: "COMBOSQUAT", brand: b, brandToken, token, distance: null, confidence: 0.6 };
        }
      }
    }
    return best;
  }

  return { skeleton, editDistance, registrableDomain, hostTokens, analyze, CONFUSABLES };
});
