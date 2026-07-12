import csv
import gzip
import json
import random
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path.home() / "AppData" / "Local" / "Temp" / "argus-new-datasets"
OUTPUT = ROOT / "datasets" / "mega_calibration_cases.json"
RUNTIME_OUTPUT = ROOT / "datasets" / "fp_context_runtime.json"
SEED = 20260711
PER_SOURCE = 10000


def truth(row, key):
    return str(row.get(key, "")).strip().lower() in {"1", "true", "yes"}


def number(row, key):
    try:
        return float(row.get(key, 0) or 0)
    except ValueError:
        return 0


def reservoir_by_label(path, compressed=False):
    rng = random.Random(SEED + (1 if compressed else 0))
    labels = {"SAFE": [], "LOW_RISK": [], "SUSPICIOUS": [], "HIGH_RISK": []}
    quotas = {"SAFE": 4000, "LOW_RISK": 3000, "SUSPICIOUS": 1800, "HIGH_RISK": 1200}
    seen = {key: 0 for key in labels}
    opener = gzip.open if compressed else open
    with opener(path, "rt", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            label = row.get("expected_label", "SAFE")
            if label not in labels:
                continue
            seen[label] += 1
            bucket = labels[label]
            quota = quotas[label]
            if len(bucket) < quota:
                bucket.append(row)
            else:
                index = rng.randrange(seen[label])
                if index < quota:
                    bucket[index] = row
    return [row for label in labels.values() for row in label]


def signals(row):
    password = truth(row, "password_field")
    otp = truth(row, "otp_field")
    payment = truth(row, "payment_field")
    sensitive = password or otp or payment or truth(row, "credential_like_text_field")
    cross = truth(row, "form_cross_unknown") or truth(row, "form_cross_domain_unknown")
    http_form = truth(row, "form_http") or truth(row, "form_http_action")
    unknown_after = truth(row, "unknown_xhr_after_sensitive") or truth(row, "third_party_xhr_after_sensitive")
    unknown_beacon = truth(row, "unknown_beacon_after_sensitive")
    protocol = str(row.get("protocol", "https")).lower()
    official = truth(row, "verified_official") or truth(row, "verified_official_hint")
    return {
        "domain": "training.invalid",
        "pageProtocol": protocol + ":",
        "isTrustedDomain": official,
        "hasPasswordField": password,
        "hasOTP": otp,
        "hasLoginKeyword": sensitive,
        "hasAdHeavySignal": str(row.get("sector", row.get("vertical", ""))).upper() == "ADVERTISING",
        "apkLinks": [{"href": "https://example.invalid/app.apk"}] if truth(row, "actual_apk_link") else [],
        "dataLeakSignals": {
            "formCount": int(sensitive),
            "sensitiveFormCount": int(sensitive),
            "crossDomainFormActionCount": int(cross),
            "httpFormActionCount": int(http_form),
            "passwordCrossDomainForm": password and cross,
            "otpOrPaymentCrossDomainForm": (otp or payment) and cross,
            "passwordHttpForm": password and http_form,
            "otpOrPaymentHttpForm": (otp or payment) and http_form,
            "credentialLikeTextFieldCount": int(truth(row, "credential_like_text_field")),
            "hiddenIframeCount": int(truth(row, "hidden_iframe_unknown")),
            "dynamicEndpointAssemblyCount": int(truth(row, "dynamic_endpoint_unknown")),
            "scriptNetworkSinkCount": int(truth(row, "dynamic_endpoint_unknown") or unknown_after or unknown_beacon),
            "externalUrlHints": ["https://unknown.invalid/collect"] if truth(row, "dynamic_endpoint_unknown") else [],
            "clipboardReadIndicator": truth(row, "clipboard_background") or truth(row, "clipboard_sent_unknown"),
            "fileMetadataHarvestIndicator": truth(row, "file_metadata_sent_unknown"),
            "wildcardPostMessageIndicator": truth(row, "wildcard_postmessage_sensitive") or truth(row, "postmessage_wildcard_sensitive")
        },
        "networkSignals": {
            "thirdPartyRequests": round(number(row, "third_party_request_count")),
            "requestsAfterFormSubmit": 3 if unknown_after else 0,
            "requestsAfterPasswordFocus": 3 if unknown_after else 0,
            "insecureSensitiveWriteRequests": int(sensitive and http_form),
            "crossDomainSensitiveWriteRequests": int(sensitive and cross),
            "beaconOrPingAfterSensitiveInput": int(unknown_beacon)
        },
        "securitySignals": {
            "hasContentSecurityPolicy": protocol == "https",
            "hasStrictTransportSecurity": protocol == "https"
        }
    }


def convert(row, source):
    label = row.get("expected_label", "SAFE")
    level = "SAFE" if label in {"SAFE", "LOW_RISK"} else label
    low = round(number(row, "recommended_score_min"))
    high = round(number(row, "recommended_score_max"))
    target = round((low + high) / 2)
    return {
        "id": f"{source}-{row.get('sample_id')}",
        "signals": signals(row),
        "expect": {"targetScore": target, "level": level, "originalLabel": label},
        "datasetSplit": row.get("dataset_split", "TRAIN")
    }


def build_runtime():
    services = {}
    with open(SOURCE / "fp" / "argus_fp_known_service_domains.csv", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            services[row["domain_or_pattern"].lower()] = {
                "category": row["service_category"],
                "adjustment": int(row["recommended_adjustment"]),
                "strongBehaviorOverride": True
            }
    rules = []
    with open(SOURCE / "fp" / "argus_fp_institutional_suffix_rules.csv", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            rules.append({"pattern": row["suffix_or_regex"], "type": row["rule_type"], "category": row["institution_category"], "adjustment": int(row["recommended_adjustment"]), "requiresHttps": truth(row, "requires_https")})
    RUNTIME_OUTPUT.write_text(json.dumps({"version": "2.0.0", "hardWhitelist": False, "services": services, "institutionalRules": rules}, separators=(",", ":")) + "\n", encoding="utf-8")


fp_rows = reservoir_by_label(SOURCE / "fp" / "argus_fp_benign_behavior_250k.csv")
cross_rows = reservoir_by_label(SOURCE / "cross" / "argus_cross_sector_behavior_1m.csv.gz", compressed=True)
cases = [convert(row, "fp") for row in fp_rows] + [convert(row, "cross") for row in cross_rows]
OUTPUT.write_text(json.dumps({"version": "mega-2.0+cross-1.0", "seed": SEED, "cases": cases}, separators=(",", ":")) + "\n", encoding="utf-8")
build_runtime()
print(f"Imported {len(cases)} stratified calibration cases to {OUTPUT}")
