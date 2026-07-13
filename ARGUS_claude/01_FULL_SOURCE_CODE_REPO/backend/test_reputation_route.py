"""Integration tests for the reputation route (P1) — canonical POST
/v1/reputation/check with the legacy /reputation alias.

Run:  cd backend && python -m pytest test_reputation_route.py    (or: python test_reputation_route.py)

Requires fastapi + httpx (see requirements.txt). Uses FastAPI's in-process TestClient,
so no running server is needed.
"""
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)

# A domain guaranteed to be on the bundled seed blocklist.
LISTED = "phishing-example.invalid"
CLEAN = "definitely-not-listed-" + "example.org"


def test_canonical_route_returns_200_and_malicious_for_listed():
    r = client.post("/v1/reputation/check", json={"host": LISTED})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["listed"] is True
    assert body["verdict"] == "malicious"
    assert body["host"] == LISTED
    assert body["matchedDomain"] == LISTED


def test_subdomain_of_listed_is_malicious():
    r = client.post("/v1/reputation/check", json={"host": "login." + LISTED})
    assert r.status_code == 200
    assert r.json()["verdict"] == "malicious"


def test_clean_host_is_unknown_not_listed():
    r = client.post("/v1/reputation/check", json={"host": CLEAN})
    assert r.status_code == 200
    body = r.json()
    assert body["listed"] is False
    assert body["verdict"] == "unknown"
    assert body["source"] == "NONE"


def test_legacy_alias_still_works():
    r = client.post("/reputation", json={"host": LISTED})
    assert r.status_code == 200
    assert r.json()["verdict"] == "malicious"


def test_domain_alias_field_accepted():
    r = client.post("/v1/reputation/check", json={"domain": LISTED})
    assert r.status_code == 200
    assert r.json()["verdict"] == "malicious"


def test_extra_fields_ignored_no_leakage():
    # Even if a client mistakenly sends extra keys, only the hostname is used and
    # nothing else is echoed back (no path/query/cookies/user data in the response).
    r = client.post("/v1/reputation/check", json={
        "host": CLEAN, "url": "https://x/secret?token=abc", "cookie": "sid=1", "password": "hunter2"
    })
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"ok", "host", "domain", "listed", "verdict", "source", "matchedDomain"}
    assert body["host"] == CLEAN
    # None of the smuggled fields are reflected anywhere in the response.
    assert "abc" not in r.text and "hunter2" not in r.text and "sid=1" not in r.text


def test_health_unaffected():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["ok"] is True


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
