import csv
import gzip
import io
import json
import math
import os
import random
import tempfile
import zipfile
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = Path.home() / "Downloads"
FP_ZIP = DOWNLOADS / "argus_fp_mega_dataset_bundle.zip"
CROSS_ZIP = DOWNLOADS / "argus_cross_sector_mega_bundle.zip"
POPULAR_ZIP = DOWNLOADS / "argus_popular_domains_10000_bundle.zip"
CACHE = Path(tempfile.gettempdir()) / "argus-full-mega-training"
STEPS = 10_000
BATCH = 2048
SEED = 20260711

FEATURES = [
    "untrusted_domain", "search_engine_page", "insecure_page", "password_field", "otp_field",
    "login_language", "suspicious_domain", "brand_like_domain", "bank_language", "store_language",
    "apk_link", "gambling_or_adult", "ad_heavy", "sensitive_form", "cross_domain_form",
    "http_form", "password_cross_domain_form", "sensitive_cross_domain_form", "sensitive_http_form",
    "credential_like_field", "hidden_frame", "external_script_credential_page", "script_network_sink",
    "external_endpoint_hint", "dynamic_endpoint", "form_value_read", "formdata_read", "storage_secret_write",
    "cookie_read", "encoded_payload", "websocket_send", "wildcard_postmessage", "clipboard_or_file_access",
    "missing_security_headers", "mixed_content", "insecure_active_content", "third_party_script_no_integrity",
    "unsandboxed_third_party_frame", "insecure_sensitive_write", "cross_domain_sensitive_write",
    "beacon_after_sensitive_input", "query_get_after_sensitive_form", "insecure_write_after_form",
    "third_party_activity_after_form", "third_party_activity_after_password", "cross_domain_redirect_after_form",
    "download_after_form", "credential_flow_combo", "fake_store_apk_combo", "sensitive_form_transport_combo",
    "form_read_relay_combo", "storage_relay_combo", "encoded_relay_combo", "websocket_relay_combo",
    "postmessage_relay_combo", "unprotected_script_credential_combo", "mixed_sensitive_combo",
    "bank_credential_combo", "generic_http_form", "recovery_relay_combo", "url_long",
    "url_ip_host", "url_obfuscation", "url_excessive_subdomains", "domain_high_digit_ratio",
    "url_credential_path", "lexical_credential_combo", "secure_same_origin_auth", "content_only"
]
IDX = {name: index for index, name in enumerate(FEATURES)}
LABEL_LEVEL = {"SAFE": "SAFE", "LOW_RISK": "SAFE", "SUSPICIOUS": "SUSPICIOUS", "HIGH_RISK": "HIGH_RISK"}


def flag(row, *keys):
    return any(str(row.get(key, "")).strip().lower() in {"1", "true", "yes"} for key in keys)


def num(row, key):
    try:
        return float(row.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def vector(row):
    x = np.zeros(len(FEATURES), dtype=np.float32)
    password = flag(row, "password_field")
    otp = flag(row, "otp_field")
    payment = flag(row, "payment_field")
    credential = flag(row, "credential_like_text_field")
    sensitive = password or otp or payment or credential
    cross = flag(row, "form_cross_unknown", "form_cross_domain_unknown")
    http_form = flag(row, "form_http", "form_http_action")
    verified = flag(row, "verified_official", "verified_official_hint")
    apk = flag(row, "actual_apk_link")
    dynamic = flag(row, "dynamic_unknown_endpoint", "dynamic_endpoint_unknown")
    unknown_xhr = flag(row, "unknown_xhr_after_sensitive", "third_party_xhr_after_sensitive")
    beacon = flag(row, "unknown_beacon_after_sensitive")
    wildcard = flag(row, "wildcard_postmessage_sensitive", "postmessage_wildcard_sensitive")
    clipboard_file = flag(row, "clipboard_background", "clipboard_sent_unknown", "file_metadata_sent_unknown")
    protocol = str(row.get("protocol", "https")).lower()
    same_origin = flag(row, "form_same_origin", "form_same_etld1")
    sector = str(row.get("sector", row.get("vertical", ""))).upper()

    def put(name, value=True):
        x[IDX[name]] = float(value)

    put("untrusted_domain", not verified)
    put("insecure_page", protocol == "http")
    put("password_field", password)
    put("otp_field", otp)
    put("login_language", sensitive)
    put("apk_link", apk)
    put("ad_heavy", sector == "ADVERTISING")
    put("sensitive_form", sensitive)
    put("cross_domain_form", cross)
    put("http_form", http_form)
    put("password_cross_domain_form", password and cross)
    put("sensitive_cross_domain_form", sensitive and cross)
    put("sensitive_http_form", sensitive and http_form)
    put("credential_like_field", credential)
    put("hidden_frame", flag(row, "hidden_iframe_unknown"))
    put("script_network_sink", dynamic or unknown_xhr or beacon)
    put("external_endpoint_hint", dynamic)
    put("dynamic_endpoint", dynamic)
    put("wildcard_postmessage", wildcard)
    put("clipboard_or_file_access", clipboard_file)
    put("insecure_sensitive_write", sensitive and http_form)
    put("cross_domain_sensitive_write", sensitive and cross)
    put("beacon_after_sensitive_input", beacon)
    put("third_party_activity_after_form", 1 if unknown_xhr else 0)
    put("third_party_activity_after_password", 1 if unknown_xhr and password else 0)
    put("credential_flow_combo", password and otp)
    put("sensitive_form_transport_combo", sensitive and (cross or http_form))
    put("postmessage_relay_combo", sensitive and wildcard)
    put("generic_http_form", http_form and not sensitive)
    put("secure_same_origin_auth", sensitive and same_origin and protocol == "https" and not cross)
    put("content_only", str(row.get("content_category_only", "NONE")).upper() != "NONE")
    return x


def target(row):
    return np.float32((num(row, "recommended_score_min") + num(row, "recommended_score_max")) / 200.0)


def split_code(value):
    return {"TRAIN": 0, "VALIDATION": 1, "TEST": 2}.get(str(value).upper(), 0)


def iter_csv_from_zip(zip_path, member, gzipped=False):
    with zipfile.ZipFile(zip_path) as archive, archive.open(member) as raw:
        stream = gzip.GzipFile(fileobj=raw) if gzipped else raw
        with io.TextIOWrapper(stream, encoding="utf-8-sig", newline="") as text:
            yield from csv.DictReader(text)


def prepare_memmaps():
    CACHE.mkdir(parents=True, exist_ok=True)
    total = 1_260_000
    x = np.memmap(CACHE / "x.f32", dtype=np.float32, mode="w+", shape=(total, len(FEATURES)))
    y = np.memmap(CACHE / "y.f32", dtype=np.float32, mode="w+", shape=(total,))
    splits = np.memmap(CACHE / "split.u8", dtype=np.uint8, mode="w+", shape=(total,))
    labels = np.memmap(CACHE / "label.u8", dtype=np.uint8, mode="w+", shape=(total,))
    index = 0
    sources = [
        (FP_ZIP, "argus_fp_benign_behavior_250k.csv", False),
        (CROSS_ZIP, "argus_cross_sector_behavior_1m.csv.gz", True),
    ]
    label_codes = {"SAFE": 0, "LOW_RISK": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2}
    for archive, member, compressed in sources:
        for row in iter_csv_from_zip(archive, member, compressed):
            x[index] = vector(row)
            y[index] = target(row)
            splits[index] = split_code(row.get("dataset_split"))
            labels[index] = label_codes.get(row.get("expected_label", "SAFE"), 0)
            index += 1
    with zipfile.ZipFile(POPULAR_ZIP) as archive:
        popular = json.loads(archive.read("argus_popular_domains_10000.json"))
    for rank, _domain in enumerate(popular["domains"], start=1):
        row = np.zeros(len(FEATURES), dtype=np.float32)
        row[IDX["untrusted_domain"]] = 1
        x[index] = row
        y[index] = 0.03
        splits[index] = 0 if rank % 10 < 8 else 1 if rank % 10 == 8 else 2
        labels[index] = 0
        index += 1
    if index != total:
        raise RuntimeError(f"Expected {total} rows, processed {index}")
    x.flush(); y.flush(); splits.flush(); labels.flush()
    return x, y, splits, labels


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


def metrics(x, y, labels, indices, means, scales, weights, bias, chunk=65536):
    totals = {"count": 0, "correct": 0, "safe": 0, "safeFp": 0, "high": 0, "highHit": 0, "mae": 0.0}
    for start in range(0, len(indices), chunk):
        ids = indices[start:start + chunk]
        pred = sigmoid(((x[ids] - means) / scales) @ weights + bias)
        scores = np.rint(pred * 100)
        levels = np.where(scores >= 70, 2, np.where(scores >= 35, 1, 0))
        actual = labels[ids]
        totals["count"] += len(ids)
        totals["correct"] += int(np.sum(levels == actual))
        totals["mae"] += float(np.sum(np.abs(pred - y[ids])))
        safe = actual == 0
        high = actual == 2
        totals["safe"] += int(np.sum(safe)); totals["safeFp"] += int(np.sum(safe & (levels > 0)))
        totals["high"] += int(np.sum(high)); totals["highHit"] += int(np.sum(high & (levels == 2)))
    n = max(1, totals["count"])
    return {
        "caseCount": totals["count"], "meanAbsoluteError": round(totals["mae"] / n, 4),
        "levelAccuracy": round(totals["correct"] / n, 4),
        "safeFalsePositiveRate": round(totals["safeFp"] / max(1, totals["safe"]), 4),
        "highRiskRecall": round(totals["highHit"] / max(1, totals["high"]), 4)
    }


def train():
    np.random.seed(SEED)
    x, y, splits, labels = prepare_memmaps()
    train_ids = np.flatnonzero(splits == 0)
    validation_ids = np.flatnonzero(splits == 1)
    test_ids = np.flatnonzero(splits == 2)
    means = np.asarray(x[train_ids].mean(axis=0), dtype=np.float32)
    scales = np.asarray(x[train_ids].std(axis=0), dtype=np.float32)
    scales[scales < 1e-6] = 1
    deployed = json.loads((ROOT / "engine" / "trained_model.json").read_text(encoding="utf-8"))
    old_means = np.asarray(deployed["means"], dtype=np.float32)
    old_scales = np.asarray(deployed["scales"], dtype=np.float32)
    old_weights = np.asarray(deployed["weights"], dtype=np.float32)
    raw_weights = old_weights / np.maximum(old_scales, 1e-6)
    raw_bias = float(deployed["bias"]) - float(np.sum(old_means * raw_weights))
    weights = raw_weights * scales
    bias = np.float32(raw_bias + float(np.sum(means * raw_weights)))
    replay = json.loads((ROOT / "datasets" / "regression_replay_vectors.json").read_text(encoding="utf-8"))
    replay_x = np.asarray([row["x"] for row in replay], dtype=np.float32)
    replay_y = np.asarray([row["y"] for row in replay], dtype=np.float32)
    replay_labels = np.asarray([0 if row["level"] == "SAFE" else 2 if row["level"] == "HIGH_RISK" else 1 for row in replay], dtype=np.uint8)
    m = np.zeros_like(weights); v = np.zeros_like(weights); mb = 0.0; vb = 0.0
    history = []
    for step in range(1, STEPS + 1):
        ids = np.random.choice(train_ids, size=1024, replace=True)
        replay_ids = np.random.choice(len(replay), size=1024, replace=True)
        raw_x = np.concatenate((np.asarray(x[ids]), replay_x[replay_ids]), axis=0)
        batch_y = np.concatenate((np.asarray(y[ids]), replay_y[replay_ids]), axis=0)
        batch_labels = np.concatenate((np.asarray(labels[ids]), replay_labels[replay_ids]), axis=0)
        xb = (raw_x - means) / scales
        pred = sigmoid(xb @ weights + bias)
        mega_weights = np.where(labels[ids] == 2, 1.5, np.where(labels[ids] == 1, 1.2, 1.0))
        replay_weights = np.where(replay_labels[replay_ids] == 0, 3.0, 2.0)
        sample_weights = np.concatenate((mega_weights, replay_weights)).astype(np.float32)
        grad_logit = (pred - batch_y) * sample_weights / float(np.sum(sample_weights))
        gw = xb.T @ grad_logit + 0.0005 * weights
        gb = float(np.sum(grad_logit))
        m = 0.9 * m + 0.1 * gw; v = 0.999 * v + 0.001 * (gw * gw)
        mb = 0.9 * mb + 0.1 * gb; vb = 0.999 * vb + 0.001 * gb * gb
        lr = 0.0002 * (1 - 0.8 * step / STEPS)
        weights -= lr * (m / (1 - 0.9 ** step)) / (np.sqrt(v / (1 - 0.999 ** step)) + 1e-8)
        bias -= lr * (mb / (1 - 0.9 ** step)) / (math.sqrt(vb / (1 - 0.999 ** step)) + 1e-8)
        if step % 500 == 0:
            loss = float(np.sum(sample_weights * (-(batch_y * np.log(pred + 1e-7) + (1 - batch_y) * np.log(1 - pred + 1e-7)))) / np.sum(sample_weights))
            history.append({"step": step, "batchLoss": round(loss, 6)})
            print(f"step {step}/{STEPS} loss={loss:.6f}", flush=True)
    model = {
        "name": "Project Argus Full Mega Risk Calibrator", "version": "5.0.0",
        "modelType": "regularized-logistic-calibrator-adam", "corpusVersion": "fp-250k+cross-sector-1m+popular-10k",
        "totalCaseCount": 1_260_000, "featureCount": len(FEATURES), "featureNames": FEATURES,
        "means": means.round(8).tolist(), "scales": scales.round(8).tolist(),
        "weights": weights.round(8).tolist(), "bias": round(float(bias), 8),
        "optimizationSteps": STEPS, "batchSize": BATCH, "seed": SEED,
        "trainCaseCount": len(train_ids), "validationCaseCount": len(validation_ids), "testCaseCount": len(test_ids),
        "trainingHistory": history,
        "metrics": {
            "fullValidation": metrics(x, y, labels, validation_ids, means, scales, weights, bias),
            "fullTest": metrics(x, y, labels, test_ids, means, scales, weights, bias)
        },
        "privacy": "Offline training only; Chrome receives weights and normalization statistics, never raw datasets."
    }
    candidate_json = ROOT / "engine" / "trained_model_candidate.json"
    candidate_js = ROOT / "engine" / "trained_model_candidate.js"
    candidate_json.write_text(json.dumps(model, separators=(",", ":")) + "\n", encoding="utf-8")
    candidate_js.write_text("self.ArgusTrainedModel = " + json.dumps(model, separators=(",", ":")) + ";\n", encoding="utf-8")
    print(json.dumps(model["metrics"], indent=2))


if __name__ == "__main__":
    train()
