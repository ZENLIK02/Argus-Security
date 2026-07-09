# Website Test Only

These pages are adversarial demo pages for testing Project Argus. They are intentionally designed to be difficult for Argus to catch because they avoid obvious indicators such as password input types, OTP words, APK links, direct cross-domain form actions, and visible phishing language.

Safety note: these pages do not send typed user values anywhere. Any network-style behavior is guarded behind `window.ARGUS_TEST_ALLOW_NETWORK === true`, which is false by default, and the demo payloads omit user-entered values.

## Pages

- `quiet-profile-sync.html`: looks like a normal profile sync form, but simulates delayed credential relay through JavaScript-built endpoints.
- `consent-mirror.html`: looks like a productivity access page, but simulates a consent and popup-message trap.
- `clipboard-vault.html`: looks like a recovery vault page, but simulates clipboard/file metadata harvesting.

Run them with a local server, for example:

```powershell
cd Desktop/Project-Argus-Extension
python -m http.server 8080
```

Then open:

```text
http://localhost:8080/Website_testonly/quiet-profile-sync.html
http://localhost:8080/Website_testonly/consent-mirror.html
http://localhost:8080/Website_testonly/clipboard-vault.html
```
