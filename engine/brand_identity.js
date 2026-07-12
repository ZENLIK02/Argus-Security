(function exposeArgusBrandIdentity(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusBrandIdentity = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createBrandIdentity() {
  "use strict";

  const PINNED_ED25519_PUBLIC_KEY = "nLdDY7aRnfbsrv5oSw793AB3U58oUDGsE5Tko0pYn3g=";
  const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
    "co.th", "or.th", "go.th", "ac.th", "in.th", "mi.th", "net.th",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "co.kr", "com.sg", "com.my", "co.nz", "co.in",
    "com.br", "com.mx", "com.tr", "com.cn", "com.hk", "com.tw", "co.za"
  ]);

  const CONTEXT_KEYWORDS = Object.freeze({
    BANKING_LENDING: ["bank", "mobile banking", "loan", "credit approval", "ธนาคาร", "สินเชื่อ", "พร้อมเพย์"],
    INVESTMENT_CRYPTO: ["investment", "broker", "trading", "guaranteed profit", "crypto", "ลงทุน", "กำไร", "คริปโต"],
    PAYMENT_WALLET: ["wallet", "payment", "pay now", "bank transfer", "connect wallet", "กระเป๋า", "ชำระเงิน", "โอนเงิน"],
    GOVERNMENT_PUBLIC_SERVICE: ["government", "tax", "police", "official notice", "กรม", "ภาษี", "ตำรวจ", "ราชการ"],
    TELECOM_UTILITY: ["mobile bill", "internet bill", "electricity", "water bill", "ค่าโทรศัพท์", "ค่าไฟ", "ค่าน้ำ"],
    SHOPPING_DELIVERY: ["parcel", "delivery fee", "redelivery", "order payment", "พัสดุ", "ค่าจัดส่ง", "เก็บเงินปลายทาง"],
    PLATFORM_ACCOUNT: ["account login", "verify account", "mailbox", "cloud storage", "เข้าสู่ระบบ", "ยืนยันบัญชี"],
    TECH_SUPPORT_SECURITY: ["technical support", "virus detected", "remote access", "security alert", "ฝ่ายสนับสนุน", "ไวรัส", "ควบคุมระยะไกล"],
    REWARD_JOB_CHARITY_FEE: ["claim reward", "job fee", "application fee", "donation", "advance fee", "รับรางวัล", "ค่าสมัครงาน", "บริจาค"]
  });

  function analyze(raw, registry) {
    const input = raw && typeof raw === "object" ? raw : {};
    const validated = validateRegistry(registry) ? registry : { brands: [] };
    const publicSuffixes = new Set(Array.from(COMMON_SECOND_LEVEL_SUFFIXES).concat(toArray(validated.multiLabelPublicSuffixes).map(normalizeDomain)));
    const domain = normalizeDomain(input.domain);
    const surface = normalizeText(input.identityTextSurface || "");
    const claimedBrands = [];
    const contexts = new Set(detectGenericContexts(surface));
    let officialDomain = false;
    let deceptiveSubdomain = false;
    let homographOrTyposquat = false;

    for (const brand of validated.brands) {
      const aliases = Array.isArray(brand.aliases) ? brand.aliases : [];
      const claimed = aliases.some((alias) => containsAlias(surface, alias));
      const isOfficial = approvedDomainsOf(brand).some((candidate) => isDomainMatch(domain, candidate));
      const domainLooksLikeBrand = looksLikeBrandDomain(domain, brand, publicSuffixes);
      if (isOfficial) officialDomain = true;
      if (!claimed && !domainLooksLikeBrand) continue;
      if (claimed) {
        const claimStrong = domainLooksLikeBrand || /\b(login|sign in|verify|secure|official|account|support|payment|wallet|banking|customer)\b|เข้าสู่ระบบ|ยืนยัน|บัญชี|ชำระ|ธนาคาร|ฝ่ายสนับสนุน/.test(surface);
        claimedBrands.push({
          brandId: String(brand.brandId),
          displayName: String(brand.displayName || brand.brandId),
          official: isOfficial,
          claimStrong,
          contexts: toArray(brand.contexts),
          visualHashes: toArray(brand.visualHashes)
        });
        toArray(brand.contexts).forEach((context) => contexts.add(context));
      }
      if (!isOfficial && domainLooksLikeBrand) homographOrTyposquat = true;
      if (!isOfficial && approvedDomainsOf(brand).some((candidate) => domain.includes(candidate))) deceptiveSubdomain = true;
    }

    const mismatchedBrands = claimedBrands.filter((brand) => !brand.official);
    const visualMatches = matchVisualHashes(toArray(input.visualHashes), claimedBrands);
    const domainMismatch = mismatchedBrands.length > 0;
    const strongMismatch = domainMismatch && (homographOrTyposquat || deceptiveSubdomain || mismatchedBrands.some((brand) => brand.claimStrong));
    const primaryContext = choosePrimaryContext(contexts, claimedBrands);

    return {
      registryVersion: String(validated.version || "unavailable"),
      officialDomain,
      claimedBrands: claimedBrands.map(({ visualHashes, ...brand }) => brand),
      claimedBrandIds: claimedBrands.map((brand) => brand.brandId),
      mismatchedBrandIds: mismatchedBrands.map((brand) => brand.brandId),
      contexts: Array.from(contexts),
      primaryContext,
      highValueContext: primaryContext !== "UNKNOWN",
      domainMismatch,
      strongMismatch,
      deceptiveSubdomain,
      homographOrTyposquat,
      visualMatches,
      visualMatch: visualMatches.length > 0,
      visualReferenceAvailable: claimedBrands.some((brand) => brand.visualHashes.length > 0)
    };
  }

  function validateRegistry(value) {
    if (!value || typeof value !== "object" || Number(value.schemaVersion) !== 1 || !Array.isArray(value.brands) || !Array.isArray(value.multiLabelPublicSuffixes)) return false;
    const expiresAt = Date.parse(String(value.expiresAt || ""));
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
    const seen = new Set();
    return value.brands.every((brand) => {
      const id = String(brand && brand.brandId || "");
      if (!id || seen.has(id) || !Array.isArray(brand.aliases) || !Array.isArray(brand.officialDomains)) return false;
      seen.add(id);
      return brand.officialDomains.every((domain) => normalizeDomain(domain) === domain);
    });
  }

  async function verifySignedEnvelope(envelope) {
    if (!envelope || typeof envelope !== "object" || !envelope.payload || !envelope.signature || typeof crypto === "undefined" || !crypto.subtle) return false;
    try {
      const key = await crypto.subtle.importKey("raw", fromBase64(PINNED_ED25519_PUBLIC_KEY), { name: "Ed25519" }, false, ["verify"]);
      const payload = new TextEncoder().encode(canonicalJson(envelope.payload));
      return crypto.subtle.verify({ name: "Ed25519" }, key, fromBase64(envelope.signature), payload);
    } catch (error) {
      return false;
    }
  }

  function detectGenericContexts(surface) {
    return Object.entries(CONTEXT_KEYWORDS)
      .filter(([, keywords]) => keywords.some((keyword) => containsAlias(surface, keyword)))
      .map(([context]) => context);
  }

  function approvedDomainsOf(brand) {
    return toArray(brand.officialDomains).concat(toArray(brand.approvedAuthDomains)).map(normalizeDomain).filter(Boolean);
  }

  function looksLikeBrandDomain(domain, brand, publicSuffixes = COMMON_SECOND_LEVEL_SUFFIXES) {
    if (!domain) return false;
    const registrable = getRegistrableDomain(domain, publicSuffixes);
    const label = registrable.split(".")[0] || "";
    const domainSkeleton = skeleton(label);
    for (const alias of toArray(brand.aliases)) {
      const aliasSkeleton = skeleton(alias).replace(/[^a-z0-9]/g, "");
      if (aliasSkeleton.length < 5) continue;
      if (domainSkeleton.includes(aliasSkeleton) || aliasSkeleton.includes(domainSkeleton)) return true;
      if (Math.abs(domainSkeleton.length - aliasSkeleton.length) <= 1 && levenshtein(domainSkeleton, aliasSkeleton) <= 1) return true;
    }
    for (const official of toArray(brand.officialDomains)) {
      const officialLabel = skeleton(getRegistrableDomain(official, publicSuffixes).split(".")[0] || "");
      if (officialLabel.length >= 5 && levenshtein(domainSkeleton, officialLabel) <= 1) return true;
    }
    return false;
  }

  function choosePrimaryContext(contexts, brands) {
    const order = [
      "BANKING_LENDING", "GOVERNMENT_PUBLIC_SERVICE", "INVESTMENT_CRYPTO", "PAYMENT_WALLET",
      "TECH_SUPPORT_SECURITY", "PLATFORM_ACCOUNT", "TELECOM_UTILITY", "SHOPPING_DELIVERY", "REWARD_JOB_CHARITY_FEE"
    ];
    const brandContexts = new Set(brands.flatMap((brand) => brand.contexts));
    return order.find((context) => brandContexts.has(context)) || order.find((context) => contexts.has(context)) || "UNKNOWN";
  }

  function matchVisualHashes(hashes, brands) {
    const matches = [];
    for (const brand of brands) {
      for (const expected of brand.visualHashes) {
        if (hashes.some((actual) => hammingHex(String(actual), String(expected)) <= 8)) {
          matches.push(brand.brandId);
          break;
        }
      }
    }
    return unique(matches);
  }

  function getRegistrableDomain(value, publicSuffixes = COMMON_SECOND_LEVEL_SUFFIXES) {
    const domain = normalizeDomain(value);
    const labels = domain.split(".").filter(Boolean);
    if (labels.length <= 2) return domain;
    const suffix2 = labels.slice(-2).join(".");
    return publicSuffixes.has(suffix2) ? labels.slice(-3).join(".") : labels.slice(-2).join(".");
  }

  function isDomainMatch(domain, expected) {
    const left = normalizeDomain(domain);
    const right = normalizeDomain(expected);
    return Boolean(left && right && (left === right || left.endsWith(`.${right}`)));
  }

  function containsAlias(surface, alias) {
    const target = normalizeText(alias);
    if (!target) return false;
    if (/^[a-z0-9 ]+$/.test(target)) {
      const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
      return new RegExp(`(?:^|[^a-z0-9])${escaped}(?:$|[^a-z0-9])`, "i").test(surface);
    }
    return surface.includes(target);
  }

  function normalizeText(value) {
    return String(value || "").normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
  }

  function normalizeDomain(value) {
    return String(value || "").toLowerCase().replace(/^\.+|\.+$/g, "");
  }

  function skeleton(value) {
    return normalizeText(value)
      .replace(/[оοՕ]/g, "o").replace(/[аαΑ]/g, "a").replace(/[еΕ]/g, "e")
      .replace(/[іΙ]/g, "i").replace(/[ѕЅ]/g, "s").replace(/[рΡ]/g, "p")
      .replace(/[сϹ]/g, "c").replace(/[хΧ]/g, "x").replace(/[уΥ]/g, "y")
      .replace(/0/g, "o").replace(/[1l|]/g, "i").replace(/3/g, "e").replace(/5/g, "s").replace(/7/g, "t")
      .replace(/[^a-z0-9]/g, "");
  }

  function levenshtein(a, b) {
    if (!a) return b.length;
    if (!b) return a.length;
    let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
    for (let i = 1; i <= a.length; i += 1) {
      const current = [i];
      for (let j = 1; j <= b.length; j += 1) {
        current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      previous = current;
    }
    return previous[b.length];
  }

  function hammingHex(left, right) {
    if (!/^[0-9a-f]{16}$/i.test(left) || !/^[0-9a-f]{16}$/i.test(right)) return Infinity;
    let distance = 0;
    for (let i = 0; i < 16; i += 1) {
      let value = parseInt(left[i], 16) ^ parseInt(right[i], 16);
      while (value) { distance += value & 1; value >>= 1; }
    }
    return distance;
  }

  function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    return JSON.stringify(value);
  }

  function fromBase64(value) {
    const binary = atob(String(value));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function toArray(value) { return Array.isArray(value) ? value.filter(Boolean) : []; }
  function unique(values) { return Array.from(new Set(values.filter(Boolean))); }

  return {
    PINNED_ED25519_PUBLIC_KEY, CONTEXT_KEYWORDS, analyze, validateRegistry, verifySignedEnvelope,
    getRegistrableDomain, isDomainMatch, containsAlias, skeleton, levenshtein, hammingHex
  };
});
