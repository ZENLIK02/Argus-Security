# Project Argus Privacy Notes

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
- Evasive Script Guard uses metadata only: counts of inline scripts, JavaScript network sinks, dynamic endpoint assembly indicators, popup-message indicators, clipboard/file metadata indicators, and credential-like field names. It does not collect typed field values.
- Adult/gambling category labels are treated as content-risk signals, not proof of phishing. Higher risk requires concrete behavior such as sensitive forms, APK links, insecure HTTP forms, hidden iframes, or suspicious third-party requests.
- The extension now uses the local Project Argus model only. There is no external AI API call and no API key requirement.
- Exported analyzer evidence contains rule identifiers, confidence, severity, category, and human-readable explanations only.
