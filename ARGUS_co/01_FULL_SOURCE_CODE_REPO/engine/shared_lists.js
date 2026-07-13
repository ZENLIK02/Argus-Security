(function exposeArgusSharedLists(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.ArgusSharedLists = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function createSharedLists() {
  "use strict";

  // Single source of truth for domain/category lists shared by content.js and
  // service_worker.js (loaded as the first content script and via importScripts).
  // Previously these were duplicated across both files and diverged (F8).

  // Baseline trusted domains. trusted_domains.json holds optional local additions
  // that the worker unions on top of this list; content.js uses this baseline.
  const TRUSTED_DOMAINS = [
    "google.com", "www.google.com", "google.co.th", "www.google.co.th", "play.google.com", "accounts.google.com",
    "bing.com", "www.bing.com", "search.brave.com", "duckduckgo.com", "www.duckduckgo.com",
    "youtube.com", "roblox.com", "create.roblox.com", "finance.yahoo.com", "yahoo.com",
    "samsung.com", "www.samsung.com", "galaxystore.samsung.com", "apps.samsung.com",
    "apple.com", "apps.apple.com", "github.com", "microsoft.com", "tiktok.com",
    "instagram.com", "facebook.com", "x.com", "twitter.com", "linkedin.com",
    "reddit.com", "discord.com", "steamcommunity.com", "steampowered.com",
    "epicgames.com", "store.epicgames.com", "mit.edu", "ieee.org", "arxiv.org",
    "kbank.co.th", "kasikornbank.com", "scb.co.th", "bangkokbank.com", "krungsri.com",
    "set.or.th", "sec.or.th", "bot.or.th", "f-droid.org", "wikipedia.org"
  ];

  const SEARCH_ENGINE_DOMAINS = [
    "google.com", "www.google.com", "google.co.th", "www.google.co.th",
    "bing.com", "www.bing.com", "search.brave.com", "duckduckgo.com", "www.duckduckgo.com"
  ];

  const KNOWN_IDENTITY_DOMAINS = ["accounts.google.com", "login.microsoftonline.com", "login.live.com", "auth0.com", "okta.com"];
  const KNOWN_PAYMENT_DOMAINS = ["stripe.com", "paypal.com", "2c2p.com", "omise.co", "adyen.com", "checkout.com"];
  const KNOWN_ANALYTICS_DOMAINS = ["google-analytics.com", "googletagmanager.com", "analytics.google.com", "sentry.io", "clarity.ms"];
  const KNOWN_AD_DOMAINS = ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com"];
  const CDN_DOMAIN_HINTS = ["cloudflare", "cloudfront", "akamai", "fastly", "jsdelivr", "unpkg", "cdnjs", "gstatic"];

  const MULTI_LABEL_SUFFIXES = [
    "co.th", "or.th", "go.th", "ac.th", "in.th",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.kr", "com.sg", "com.my", "co.nz",
    "github.io", "pages.dev", "vercel.app", "netlify.app", "appspot.com", "cloudfront.net"
  ];

  const SUSPICIOUS_DOMAIN_WORDS = [
    "verify", "secure", "update", "login", "account", "wallet", "bank",
    "play-store", "google-play", "galaxy-store", "apk", "support-secure"
  ];

  const GAMBLING_DOMAIN_PATTERNS = [
    "casino", "slot", "bet", "jackpot", "ufa", "pgslot", "sbobet", "game66", "mahagame", "sagame", "hydra888", "kingdom66", "lockdown168", "brazil999"
  ];

  const ADULT_DOMAIN_PATTERNS = ["porn", "xxx", "adult", "18plus"];

  // High-value brand impersonation targets (registrable domains) for the offline
  // homoglyph/typosquat detector. Curated: big tech, payment, marketplaces, crypto,
  // and Thai banks. Their own domains + subdomains are never flagged.
  const LOOKALIKE_BRANDS = [
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "netflix.com", "amazon.com", "paypal.com", "stripe.com", "binance.com", "coinbase.com",
    "steampowered.com", "roblox.com", "discord.com", "tiktok.com", "line.me",
    "kbank.co.th", "kasikornbank.com", "scb.co.th", "bangkokbank.com", "krungsri.com",
    "ktb.co.th", "gsb.or.th", "promptpay.io"
  ];

  const KEYWORDS = {
    otp: ["otp", "one-time password", "one time password", "verification code", "verify code", "security code", "2fa", "mfa"],
    login: ["login", "log in", "sign in", "verify account", "account verification", "account center", "member login", "เข้าสู่ระบบ", "สมัครสมาชิก", "ยืนยันบัญชี"],
    appStore: ["google play", "play store", "galaxy store", "samsung store", "app store", "install app", "update app"],
    gambling: ["casino", "gambling", "betting", "sportsbook", "slot", "slots", "poker", "baccarat", "jackpot", "ufa", "pgslot", "sbobet", "บาคาร่า", "คาสิโน", "สล็อต", "พนัน", "เว็บพนัน", "เดิมพัน", "แทงบอล", "หวย", "รูเล็ต", "ฝากถอน", "เครดิตฟรี", "โปรโมชั่น", "แจ็คพอต"],
    adult: ["adult", "18+", "xxx", "porn", "sex", "onlyfans", "คลิปหลุด", "เว็บโป๊", "หนังโป๊"],
    banking: ["bank", "mobile banking", "verify bank account", "account locked", "transfer", "wallet", "ธนาคาร", "บัญชีถูกล็อก", "โอนเงิน", "พร้อมเพย์"],
    investment: ["guaranteed profit", "double your money", "crypto bonus", "fast return", "wallet connect", "ลงทุน", "กำไรแน่นอน", "ถอนเงินทันที", "คริปโต"],
    techSupport: ["your device is infected", "call support", "virus detected", "security alert", "remote support", "pc cleaner"],
    popupAbuse: ["allow notifications", "click allow", "continue to download", "your phone is infected", "download now", "skip ad", "fake download", "กดอนุญาต", "กดข้ามโฆษณา"],
    fakeShopping: ["flash sale", "90% off", "limited offer", "official sale", "brand outlet", "clearance sale", "ของแท้ราคาถูก"],
    prize: ["you won", "claim reward", "free iphone", "lucky winner", "giveaway", "รับรางวัล", "ของแจก"],
    pirated: ["crack", "keygen", "serial key", "free premium", "patched", "mod apk"],
    paymentWallet: ["digital wallet", "connect wallet", "pay now", "payment required", "wallet verification", "กระเป๋าเงิน", "ชำระเงิน", "ยืนยันกระเป๋า"],
    government: ["government notice", "tax refund", "tax payment", "police notice", "official summons", "กรมสรรพากร", "คืนภาษี", "ชำระภาษี", "หมายเรียก", "หน่วยงานรัฐ"],
    telecomUtility: ["mobile bill", "internet bill", "electricity bill", "water bill", "service suspension", "ค่าโทรศัพท์", "ค่าอินเทอร์เน็ต", "ค่าไฟ", "ค่าน้ำ", "ระงับบริการ"],
    delivery: ["parcel delivery", "redelivery fee", "delivery payment", "customs fee", "พัสดุ", "ค่าจัดส่ง", "ค่าศุลกากร", "เก็บเงินปลายทาง"],
    platformAccount: ["verify your account", "mailbox login", "cloud account", "account suspended", "ยืนยันบัญชี", "บัญชีถูกระงับ", "เข้าสู่ระบบอีเมล"],
    jobCharityFee: ["job application fee", "advance fee", "processing fee", "charity donation", "ค่าสมัครงาน", "ค่าดำเนินการ", "ค่ามัดจำ", "บริจาค"],
    ad: ["ad", "ads", "advert", "advertisement", "banner", "sponsor", "sponsored", "promo", "promotion", "popup", "pop-up", "affiliate", "โฆษณา", "สมัครคลิก", "เครดิตฟรี", "ฝากถอน", "ชวนเพื่อน", "รับเงินคืน"]
  };

  return {
    TRUSTED_DOMAINS, SEARCH_ENGINE_DOMAINS,
    KNOWN_IDENTITY_DOMAINS, KNOWN_PAYMENT_DOMAINS, KNOWN_ANALYTICS_DOMAINS, KNOWN_AD_DOMAINS, CDN_DOMAIN_HINTS,
    MULTI_LABEL_SUFFIXES, SUSPICIOUS_DOMAIN_WORDS, GAMBLING_DOMAIN_PATTERNS, ADULT_DOMAIN_PATTERNS, KEYWORDS,
    LOOKALIKE_BRANDS
  };
});
