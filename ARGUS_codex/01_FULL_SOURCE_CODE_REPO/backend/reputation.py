from __future__ import annotations

from pathlib import Path
import json
import os
import re
from typing import Any
from urllib.parse import urlencode
from urllib.request import urlopen


REPUTATION_SEED_FILE = Path(__file__).resolve().parent / "reputation_seed.json"


def normalize_hostname(value: str) -> str:
    raw = value.strip().lower().rstrip(".")
    if "://" in raw or "/" in raw or "?" in raw or "#" in raw or "@" in raw:
        raise ValueError("hostname must not include a URL path, query, fragment, or credentials")
    try:
        hostname = raw.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("hostname is not valid IDNA") from error
    if not hostname or len(hostname) > 253 or not re.fullmatch(r"[a-z0-9.-]+", hostname):
        raise ValueError("hostname is invalid")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in hostname.split(".")):
        raise ValueError("hostname labels are invalid")
    return hostname


def load_reputation_seed(path: Path = REPUTATION_SEED_FILE) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries = raw.get("entries", []) if isinstance(raw, dict) else []
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            result[normalize_hostname(str(entry.get("hostname", "")))] = entry
        except ValueError:
            continue
    return result


def query_google_web_risk(hostname: str) -> dict[str, Any]:
    api_key = os.getenv("ARGUS_WEBRISK_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "malicious": False, "categories": []}
    query = urlencode({
        "uri": f"https://{hostname}/",
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        "key": api_key,
    }, doseq=True)
    try:
        with urlopen(f"https://webrisk.googleapis.com/v1/uris:search?{query}", timeout=2.0) as response:
            payload = json.loads(response.read(262144).decode("utf-8"))
    except Exception:
        return {"available": False, "malicious": False, "categories": []}
    threat = payload.get("threat", {}) if isinstance(payload, dict) else {}
    categories = [str(item) for item in threat.get("threatTypes", [])]
    return {"available": True, "malicious": bool(categories), "categories": categories}
