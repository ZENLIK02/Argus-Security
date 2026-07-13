# Recovery and resume

Public browser acceptance is blocked by `ERR_NETWORK_ACCESS_DENIED`. Resume in a workspace-write runtime that permits Chromium outbound HTTPS, then run:

```powershell
$env:ARGUS_CHROME_PATH='C:\path\to\playwright\chromium\chrome.exe'
node scripts\night_autofix_controller.js
```

Do not use a personal Chrome profile. To reverse retained repairs, manually revert only the focused hunks in `engine/evidence_decision_policy.js` and `popup.js`; do not reset the dirty worktree.
