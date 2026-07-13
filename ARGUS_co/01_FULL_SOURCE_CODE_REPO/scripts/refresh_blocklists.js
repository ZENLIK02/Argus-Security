"use strict";

// Refresh the local phishing/malware blocklist used by the backend /reputation
// endpoint (P1). Fetches public feeds and writes one-domain-per-line files into
// backend/data/blocklists/. No API key required for the default feeds.
//
//   node scripts/refresh_blocklists.js
//
// Then either restart the backend or POST http://localhost:8000/reputation/reload.
//
// PhishTank (https://phishtank.org/developer_info.php) and Google Safe Browsing
// require API keys and are intentionally NOT fetched here; add them similarly if you
// have keys. Requires Node 18+ (global fetch).

const fs = require("fs");
const path = require("path");

const OUT_DIR = path.resolve(__dirname, "..", "backend", "data", "blocklists");

// Public, no-key feeds. Each returns a list of URLs (or "#"-commented lines).
const FEEDS = [
  { name: "urlhaus", url: "https://urlhaus.abuse.ch/downloads/text_online/" },
  { name: "openphish", url: "https://openphish.com/feed.txt" }
];

function hostnameOf(line) {
  const value = String(line || "").trim();
  if (!value || value.startsWith("#")) return "";
  try {
    return new URL(value).hostname.toLowerCase().replace(/^\.+|\.+$/g, "");
  } catch (error) {
    // Some feeds list bare domains rather than full URLs.
    return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value) ? value.toLowerCase() : "";
  }
}

async function refreshFeed(feed) {
  const response = await fetch(feed.url, { headers: { "User-Agent": "ProjectArgus/1.0 (local blocklist refresh)" } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const text = await response.text();
  const domains = new Set();
  for (const line of text.split(/\r?\n/)) {
    const host = hostnameOf(line);
    if (host) domains.add(host);
  }
  const sorted = Array.from(domains).sort();
  const header = `# ${feed.name} — refreshed ${new Date().toISOString()} — ${sorted.length} domains\n`;
  fs.writeFileSync(path.join(OUT_DIR, `${feed.name}.txt`), header + sorted.join("\n") + "\n", "utf8");
  return sorted.length;
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  let total = 0;
  for (const feed of FEEDS) {
    try {
      const count = await refreshFeed(feed);
      total += count;
      console.log(`OK   ${feed.name}: ${count} domains`);
    } catch (error) {
      console.error(`FAIL ${feed.name}: ${error.message} (kept previous file if any)`);
    }
  }
  console.log(`Done. ~${total} domains written to ${OUT_DIR}`);
  console.log("Restart the backend or POST http://localhost:8000/reputation/reload to apply.");
}

main().catch((error) => { console.error(error); process.exit(1); });
