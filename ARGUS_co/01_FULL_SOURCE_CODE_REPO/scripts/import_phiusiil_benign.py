"""Create a deterministic 100-case benign URL holdout from the UCI PhiUSIIL CSV."""

import csv
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "datasets" / "phiusiil_benign_cases.json"
SUSPICIOUS_WORDS = (
    "verify", "secure", "update", "login", "account", "wallet", "bank",
    "play-store", "google-play", "galaxy-store", "apk", "support-secure",
)


def to_int(value):
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/import_phiusiil_benign.py <PhiUSIIL CSV path>")

    csv_path = Path(sys.argv[1]).resolve()
    core = json.loads((ROOT / "datasets" / "exfiltration_eval_cases.json").read_text(encoding="utf-8"))
    template = next(case["signals"] for case in core["cases"] if case["id"] == "safe-static-https")
    candidates = []
    seen_domains = set()

    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            if str(row.get("label", "")).strip() != "1":
                continue
            password = to_int(row.get("HasPasswordField")) > 0
            external_form = to_int(row.get("HasExternalFormSubmit")) > 0
            if password and external_form:
                continue

            try:
                parsed = urlsplit(row.get("URL", ""))
            except ValueError:
                continue
            domain = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            path = parsed.path or "/"
            sanitized_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
            risk_words = [word for word in SUSPICIOUS_WORDS if word in domain]
            login_hint = any(word in f"{domain} {path}".lower() for word in ("login", "signin", "sign-in", "account", "auth"))
            popup_count = to_int(row.get("NoOfPopup"))
            challenge_score = (
                password * 12 + external_form * 6 + (parsed.scheme == "http") * 3 +
                min(6, popup_count) + min(6, len(risk_words) * 3) +
                min(5, to_int(row.get("NoOfiFrame"))) + min(5, to_int(row.get("NoOfJS")) // 10)
            )
            stable_order = hashlib.sha256(sanitized_url.encode("utf-8", errors="ignore")).hexdigest()

            signals = json.loads(json.dumps(template))
            signals.update({
                "url": sanitized_url,
                "domain": domain,
                "pathname": path,
                "pageProtocol": f"{parsed.scheme}:",
                "hasPasswordField": password,
                "hasLoginKeyword": login_hint,
                "suspiciousDomainSignals": [f"Domain contains generic word: {word}." for word in risk_words],
                "hasAdHeavySignal": popup_count >= 5,
            })
            signals["dataLeakSignals"].update({
                "formCount": 1 if to_int(row.get("HasSubmitButton")) else 0,
                "sensitiveFormCount": 1 if password else 0,
                "crossDomainFormActionCount": 1 if external_form else 0,
                "hiddenInputCount": 1 if to_int(row.get("HasHiddenFields")) else 0,
                "externalScriptCount": min(5, to_int(row.get("NoOfJS"))),
                "thirdPartyIframeCount": min(5, to_int(row.get("NoOfiFrame"))),
            })
            candidates.append((challenge_score, stable_order, signals))

    selected = sorted(candidates, key=lambda item: (-item[0], item[1]))[:100]
    if len(selected) != 100:
        raise RuntimeError(f"Expected 100 unique legitimate URL cases, found {len(selected)}")

    cases = [
        {
            "id": f"phiusiil-legitimate-{index:03d}",
            "group": "phiusiil-legitimate-holdout",
            "signals": signals,
            "expect": {"level": "SAFE", "max": 34, "targetScore": 8},
            "sourceTags": ["UCI_PHIUSIIL_LEGITIMATE", "CC_BY_4_0"],
        }
        for index, (_, _, signals) in enumerate(selected, start=1)
    ]
    output = {
        "name": "Project Argus PhiUSIIL Legitimate URL Holdout",
        "version": "1.0.0",
        "source": "UCI Machine Learning Repository dataset 967",
        "license": "CC BY 4.0",
        "privacy": "Public URLs sanitized to scheme, host, and path. Query strings and fragments are removed.",
        "cases": cases,
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Imported {len(cases)} deterministic legitimate URL cases into {OUTPUT}")


if __name__ == "__main__":
    main()
