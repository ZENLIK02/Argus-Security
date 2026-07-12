from pathlib import Path
import os
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import reputation  # noqa: E402


seed = reputation.load_reputation_seed()
assert len(seed) == 10
assert reputation.normalize_hostname("Sexy365Bet.NET.") == "sexy365bet.net"
assert seed["sexy365bet.net"]["verdict"] == "RISKY_CONTEXT"

for unsafe in ("https://example.com/path", "example.com/path", "user@example.com", "example.com?q=secret"):
    try:
        reputation.normalize_hostname(unsafe)
    except ValueError:
        pass
    else:
        raise AssertionError(f"URL-like reputation input was accepted: {unsafe}")

os.environ.pop("ARGUS_WEBRISK_API_KEY", None)
assert reputation.query_google_web_risk("example.com") == {
    "available": False,
    "malicious": False,
    "categories": [],
}

print("PASS backend reputation hostname privacy, reviewed seeds, and offline fallback.")
