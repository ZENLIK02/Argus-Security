# Project Argus Privacy Notes

Evidence-first report schema `2` may include a numeric/boolean feature vector, evidence IDs/groups, before/after policy scores, destination roles, scan phase, opaque navigation ID, frame ID, model/policy versions, and privacy-safe timeline metadata. It excludes typed values, passwords, OTPs, cookies, authorization headers, request bodies, clipboard contents, file contents, and private query-string values.

False-positive labels are stored as `FALSE_POSITIVE_UNREVIEWED` with `reviewRequired: true`. They must be manually verified before retraining because user-submitted labels can be mistaken or intentionally poisoned.

Project Argus is designed to analyze security signals, not private user data.

- It does not collect typed usernames.
- It does not collect typed passwords.
- It does not collect OTP or verification-code values.
- It does not collect cookies, tokens, localStorage, or sessionStorage.
- It does not collect private messages.
- It does not send full page text to any external service. Local keyword checks are reduced to matched risk keywords before messaging inside the extension.
- It does not read request bodies, response bodies, or request headers.
- It only uses metadata and minimized risk indicators such as domain, URL path, password-field presence, OTP keyword presence, APK links, category keywords, ad-heavy layout signals, sanitized form action URLs, third-party iframe/script counts, and request counts.
- Data Leak Guard uses metadata only: form action protocol/host/path, cross-domain form counts, HTTP form counts, hidden iframe counts, external script counts, third-party request counts, and request timing after form/password interaction.
- Temporal correlation retains only event types and timestamps for a 30-second per-tab window. It does not retain field values or network payloads.
- Network protection checks retain only counters and booleans derived from protocol, HTTP method, resource type, same-site/cross-domain relationship, query presence, and recent sensitive-form interaction. Query strings themselves are not retained.
- Evasive Script Guard uses metadata only: counts of inline scripts, JavaScript network sinks, dynamic endpoint assembly indicators, popup-message indicators, clipboard/file metadata indicators, and credential-like field names. It does not collect typed field values.
- Browser Protection Analyzer records only header-name presence, mixed-content counters, script integrity-attribute presence, and iframe sandbox-attribute presence. Header values are not retained.
- Local calibration uses 69 numeric/boolean features. It never receives typed values, storage values, cookies, payloads, or full page text.
- Query and hash routes are distinguished only by a non-reversible in-memory fingerprint used to prevent stale scan reuse.
- Public PhiUSIIL benign holdout URLs are reduced to scheme, host, and path. Query strings and fragments are removed before storage.
- Adult/gambling category labels are treated as content-risk signals, not proof of phishing. Higher risk requires concrete behavior such as sensitive forms, APK links, insecure HTTP forms, hidden iframes, or suspicious third-party requests.
- The extension now uses the local Project Argus model only. There is no external AI API call and no API key requirement.
- Exported analyzer evidence contains rule identifiers, confidence, severity, category, and human-readable explanations only.
