"""Integration tests for the reputation route — canonical POST
/v1/reputation/check with the legacy /reputation alias.

Run:  cd backend && python -m pytest test_reputation_route.py    (or: python test_reputation_route.py)

Requires fastapi + httpx (see requirements.txt). Uses FastAPI's in-process TestClient,
so no running server is needed.

Unified graded schema (ARGUS 6.0.0): verdict UNKNOWN | TRUSTED | RISKY_CONTEXT |
MALICIOUS; `listed` mirrors verdict == MALICIOUS. Resolution order: local blocklist
-> optional Google Web Risk -> reviewed seed -> UNKNOWN.
"""
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)

# A domain guaranteed to be on the bundled seed blocklist.
LISTED = "phishing-example.invalid"
# A domain from the reviewed reputation seed (RISKY_CONTEXT tier).
SEEDED = "sexy365bet.net"
CLEAN = "definitely-not-listed-" + "example.org"

EXPECTED_KEYS = {
    "ok", "hostname", "host", "domain", "listed", "verdict", "confidence",
    "sources", "source", "matchedDomain", "categories", "firstSeen", "lastSeen",
    "checkedAt",
}


def test_canonical_route_returns_200_and_malicious_for_listed():
    r = client.post("/v1/reputation/check", json={"hostname": LISTED})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["listed"] is True
    assert body["verdict"] == "MALICIOUS"
    assert body["hostname"] == LISTED
    assert body["host"] == LISTED
    assert body["matchedDomain"] == LISTED
    assert body["source"] == "LOCAL_BLOCKLIST"


def test_subdomain_of_listed_is_malicious():
    r = client.post("/v1/reputation/check", json={"hostname": "login." + LISTED})
    assert r.status_code == 200
    assert r.json()["verdict"] == "MALICIOUS"


def test_clean_host_is_unknown_not_listed():
    r = client.post("/v1/reputation/check", json={"hostname": CLEAN})
    assert r.status_code == 200
    body = r.json()
    assert body["listed"] is False
    assert body["verdict"] == "UNKNOWN"
    assert body["source"] == "NONE"


def test_seeded_host_is_risky_context_not_listed():
    r = client.post("/v1/reputation/check", json={"hostname": SEEDED})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "RISKY_CONTEXT"
    assert body["listed"] is False
    assert body["confidence"] == "HIGH"
    assert body["matchedDomain"] == SEEDED


def test_seeded_subdomain_matches_parent():
    r = client.post("/v1/reputation/check", json={"hostname": "promo." + SEEDED})
    assert r.status_code == 200
    assert r.json()["verdict"] == "RISKY_CONTEXT"


def test_legacy_alias_still_works():
    r = client.post("/reputation", json={"host": LISTED})
    assert r.status_code == 200
    assert r.json()["verdict"] == "MALICIOUS"


def test_host_and_domain_alias_fields_accepted():
    for field in ("host", "domain"):
        r = client.post("/v1/reputation/check", json={field: LISTED})
        assert r.status_code == 200
        assert r.json()["verdict"] == "MALICIOUS"


def test_idna_hostname_is_normalized():
    r = client.post("/v1/reputation/check", json={"hostname": "Sexy365Bet.NET."})
    assert r.status_code == 200
    body = r.json()
    assert body["hostname"] == SEEDED
    assert body["verdict"] == "RISKY_CONTEXT"


def test_url_like_input_resolves_unknown():
    # URL-shaped input fails strict normalization and must degrade to UNKNOWN —
    # never echo the path/query or treat it as a hostname match.
    r = client.post("/v1/reputation/check", json={"hostname": "https://evil.example/steal?t=1"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "UNKNOWN"
    assert "steal" not in r.json()["matchedDomain"]


def test_extra_fields_ignored_no_leakage():
    # Even if a client mistakenly sends extra keys, only the hostname is used and
    # nothing else is echoed back (no path/query/cookies/user data in the response).
    r = client.post("/v1/reputation/check", json={
        "hostname": CLEAN, "url": "https://x/secret?token=abc", "cookie": "sid=1", "password": "hunter2"
    })
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == EXPECTED_KEYS
    assert body["hostname"] == CLEAN
    # None of the smuggled fields are reflected anywhere in the response.
    assert "abc" not in r.text and "hunter2" not in r.text and "sid=1" not in r.text


def test_health_reports_blocklist_and_seed():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["blocklistDomains"] >= 1
    assert body["reputationSeedEntries"] >= 1


def _run_all():
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"{'ALL PASS' if failures == 0 else f'{failures} FAILED'}")
    return failures


if __name__ == "__main__":
    import sys
    sys.exit(1 if _run_all() else 0)
