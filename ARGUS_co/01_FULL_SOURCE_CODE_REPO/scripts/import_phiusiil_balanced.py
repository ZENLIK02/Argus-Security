"""Create deterministic 500 legitimate and 500 phishing URL seeds from UCI PhiUSIIL."""

import csv
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "datasets" / "phiusiil_balanced_url_seeds.json"
NUMERIC_FIELDS = (
    "URLLength", "DomainLength", "IsDomainIP", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "URLSimilarityIndex", "TLDLegitimateProb", "IsHTTPS",
    "NoOfURLRedirect", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSubmitButton", "HasHiddenFields", "HasPasswordField", "NoOfJS",
)


def to_number(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/import_phiusiil_balanced.py <PhiUSIIL CSV path>")

    buckets = {"SAFE": [], "PHISHING": []}
    seen = {"SAFE": set(), "PHISHING": set()}
    with Path(sys.argv[1]).resolve().open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            label = "SAFE" if str(row.get("label", "")).strip() == "1" else "PHISHING"
            try:
                parsed = urlsplit(row.get("URL", ""))
            except ValueError:
                continue
            domain = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or not domain or domain in seen[label]:
                continue
            seen[label].add(domain)
            path = parsed.path or "/"
            sanitized_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
            record = {
                "url": sanitized_url,
                "domain": domain,
                "pathname": path,
                "pageProtocol": f"{parsed.scheme}:",
                "features": {field: to_number(row.get(field)) for field in NUMERIC_FIELDS},
            }
            stable_order = hashlib.sha256(f"{label}:{sanitized_url}".encode("utf-8", errors="ignore")).hexdigest()
            buckets[label].append((stable_order, record))

    records = []
    for label in ("SAFE", "PHISHING"):
        selected = [record for _, record in sorted(buckets[label], key=lambda item: item[0])[:500]]
        if len(selected) != 500:
            raise RuntimeError(f"Expected 500 unique {label} URLs, found {len(selected)}")
        for index, record in enumerate(selected, start=1):
            records.append({"id": f"phiusiil-{label.lower()}-{index:03d}", "label": label, **record})

    output = {
        "name": "Project Argus PhiUSIIL Balanced URL Seeds",
        "version": "1.0.0",
        "source": "UCI Machine Learning Repository dataset 967",
        "license": "CC BY 4.0",
        "privacy": "Public URLs sanitized to scheme, host, and path. Query strings and fragments are removed.",
        "records": records,
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Imported {len(records)} balanced URL seeds into {OUTPUT}")


if __name__ == "__main__":
    main()
