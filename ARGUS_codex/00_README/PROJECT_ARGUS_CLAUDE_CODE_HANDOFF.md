# Project Argus - Full Claude Code Handoff

เอกสารนี้สรุปงานที่ทำร่วมกันตั้งแต่เริ่มต้นจนถึงสถานะล่าสุด เพื่อให้ Claude Code รับช่วงต่อได้โดยไม่ต้องเดาประวัติ ความต้องการของผู้ใช้ หรือข้อจำกัดของระบบ

อัปเดตล่าสุด: 12 กรกฎาคม 2026

## 1. Project Location และสถานะจริง

- โปรเจกต์หลัก: `C:\Users\User\Desktop\Project-Argus-Extension`
- ZIP ที่เคยใช้สำหรับนำเสนอ: `C:\Users\User\Desktop\Project-Argus-Extension.zip`
- Git remote ปัจจุบัน: `https://github.com/ZENLIK02/Argus-Security.git`
- Commit ล่าสุดที่อยู่ใน Git: `efcfa0a Remove adversarial website test folder`
- Manifest ปัจจุบัน: `5.1.1`
- Local trained model: `5.0.0`
- Evidence decision policy: `evidence-first-v2`
- โปรเจกต์มี working tree ที่ dirty มาก ทั้ง modified และ untracked files
- การแก้ล่าสุดหลัง commit `efcfa0a` ยังไม่ได้ commit และยังไม่ได้ push
- ห้าม reset, checkout หรือทิ้งไฟล์ใน working tree เพราะมีงานล่าสุดจำนวนมากที่ยังไม่อยู่ใน Git
- `Website_testonly` ยังอยู่ในเครื่อง แต่ถูกลบออกจาก Git ใน commit ล่าสุดตามคำขอเดิม

ข้อควรตรวจทันทีเมื่อ Claude Code เริ่มทำงาน:

```powershell
cd C:\Users\User\Desktop\Project-Argus-Extension
git status --short
git remote -v
git log -1 --oneline
```

## 2. เป้าหมายของ Project Argus

Project Argus เป็น Chrome Extension สำหรับตรวจความเสี่ยงของหน้าเว็บแบบ local-first โดยเน้น:

- การดักหรือส่งข้อมูลสำคัญออกจากหน้าเว็บ
- password, OTP, payment, recovery secret และ credential forms
- HTTP หรือ unencrypted sensitive submission
- cross-domain form/write หลังผู้ใช้กรอกหรือ submit ข้อมูล
- beacon, ping, query-bearing pixel และ request หลัง sensitive interaction
- phishing, fake banking, fake app store และ APK download
- script relay, dynamic endpoint, WebSocket, postMessage, clipboard/storage intent
- stale result และ evidence จาก tab/page เก่าต้องไม่ตามไปหน้าใหม่
- ลด false positive บนเว็บทั่วไปให้มากที่สุด

ระบบนี้เป็น prototype ด้าน browser security ไม่ใช่ antivirus เต็มรูปแบบ และไม่สามารถอ่านข้อความ TLS, request body, password หรือ packet payload แบบ Wireshark ได้

## 3. สิ่งที่ทำมาตั้งแต่ช่วงแรก

### 3.1 ทำให้ Chrome Extension โหลดได้

เริ่มจากซ่อมโครงสร้าง Manifest V3 และไฟล์หลัก:

- `manifest.json`
- `content.js`
- `service_worker.js`
- `popup.html`
- `popup.js`
- `style.css`
- `test-site/`

แก้ path ของ CSS/JavaScript, ตรวจ JSON, แก้นามสกุลไฟล์ และทำ ZIP สำหรับ Load unpacked/นำเสนอ

### 3.2 Rule-based detector รุ่นแรก

เพิ่มการตรวจ:

- URL และ domain
- password fields
- OTP/verification wording
- login/sign-in/verify language
- `.apk` href จริง
- fake app-store language
- cross-domain และ HTTP form
- gambling/adult/ad-heavy content

ช่วงแรกคะแนนพึ่ง keyword/category มากเกินไป ทำให้เว็บพนันหรือเว็บรูปเยอะถูกตีความแรงเกินจริง ต่อมาผู้ใช้กำหนดให้ลด priority ของ content category ลงมาก

### 3.3 OpenAI backend ที่เคยลอง

เคยสร้าง FastAPI backend ที่เรียก OpenAI API เพื่อช่วย classify หน้าเว็บ และ extension จะเรียก backend เมื่อ rule score ผ่าน threshold

ปัญหาที่พบ:

- AI ให้ 100/100 กับเว็บจำนวนมาก
- false positive สูง
- การใช้ system prompt อย่างเดียวไม่พอควบคุมการตัดสินใจ
- backend online/offline ทำให้ behavior ต่างกัน
- ผู้ใช้ไม่ต้องการให้ external model เป็นผู้ตัดสินหลัก

ภายหลังผู้ใช้สั่งลบ OpenAI ออกทั้งหมด เหลือ local model ของ Project Argus เท่านั้น

สถานะปัจจุบัน:

- ไม่มี OpenAI call ใน extension หรือ backend
- ไม่มี API key ที่ควรอยู่ในไฟล์
- FastAPI backend ปัจจุบันเป็น local demo server, false-positive feedback collector และ local result endpoint เท่านั้น
- ผู้ใช้เคยส่ง API key ในแชต แต่ห้ามนำ key นั้นกลับมาใช้หรือบันทึกลง repository
- ควรถือว่า key ที่เคยเปิดเผยต้อง revoke/rotate

### 3.4 UI badge และ popup

พัฒนา UI หลายรอบจน preference ชัดเจน:

- badge เล็กอยู่มุมล่างซ้าย
- มี animation ตอนปรากฏ
- แสดง status และ score เช่น `SAFE 0/100`
- คลิก badge เพื่อเปิด panel รายละเอียด
- panel แสดงเหตุผลที่ Argus คิดแบบนั้น
- สีต้องตรงกับระดับ: เขียว = SAFE, เหลือง = SUSPICIOUS/MONITORING, แดง = HIGH_RISK
- ผู้ใช้ชอบ UI สไตล์เวอร์ชัน 3/เวอร์ชันเก่า
- ไม่ต้องการ popup/notification อัตโนมัติด้านขวาบน
- automatic top-right warning overlay ถูกถอดออก
- การเตือนและรายละเอียดควรอยู่กับ badge/detail panel และ popup dashboard

### 3.5 Options, QA และ release preparation

เพิ่ม:

- Options page
- warning threshold
- show SAFE badge
- demo mode
- progressive observation
- observation duration
- false-positive feedback endpoint
- shadow comparison
- Export Scan Report เป็น JSON
- Clear Last Scan
- Report False Positive
- QA checklist
- release checklist
- ZIP build/validation scripts

### 3.6 False-positive reporting

เมื่อผู้ใช้กด Report False Positive:

- เก็บข้อมูลที่ผ่าน privacy filter ใน `chrome.storage.local`
- ถ้า backend เปิดอยู่ จะส่งไป `http://localhost:8000/feedback/false-positive`
- backend เก็บใน `backend/data/false_positive_reports.jsonl`
- label ต้องเป็น unreviewed และห้ามนำไป train อัตโนมัติโดยไม่ review เพื่อป้องกัน data poisoning
- ไม่เก็บ password, OTP, cookies, request body, query string หรือ private content

### 3.7 Dataset และ local model

ผู้ใช้ให้ dataset bundles หลายชุด:

- popular domains ประมาณ 10,000 domains
- false-positive mega dataset
- cross-sector mega dataset
- phishing/benign URL seeds และ synthetic browser-observable cases

สิ่งที่ทำ:

- import และ normalize dataset สำหรับ offline training
- ไม่ใส่ raw dataset เข้า runtime ของ Chrome Extension
- สร้าง feature extractor 69 features
- train regularized logistic calibrator แบบ local
- ใช้ประมาณ 1,260,000 training records
- ทำ 10,000 Adam optimization updates
- เพิ่ม regression replay เพื่อกัน catastrophic forgetting
- Chrome runtime โหลดเฉพาะ `trained_model.js/json` และ normalization weights

Model เป็น calibrator/advisory producer ไม่ใช่ final warning authority

### 3.8 Evidence-first architecture

ระบบถูกเปลี่ยนจาก score-first เป็น evidence-first:

```text
content.js + Chrome webRequest metadata
  -> normalization
  -> modular analyzers in engine/argus_engine.js
  -> local model advisory score
  -> engine/evidence_decision_policy.js
  -> final score/status
  -> per-tab storage
  -> badge/detail panel and popup
```

หลักสำคัญ:

- `HIGH_RISK` ต้องมี direct browser-observable evidence
- `SUSPICIOUS` ต้องมี evidence ที่ correlate กันมากกว่าหนึ่งกลุ่ม และต้องมี observed behavior อย่างน้อยหนึ่งกลุ่ม
- model-only ห้ามเตือน
- gambling/adult/images/ads อย่างเดียวห้ามเป็นเหตุหลักของ warning
- trusted/search pages มี false-positive guard แต่ decisive behavior ยังสามารถ override ได้

### 3.9 Navigation isolation

เคยเกิดปัญหาคะแนนจากหน้าเก่าตามไปหน้าใหม่ จึงเพิ่ม:

- `navigation_session_guard.js`
- navigation ID ต่อ tab/page
- page key และ privacy-safe route fingerprint
- reset network counters และ stored scan เมื่อ full navigation หรือ SPA route เปลี่ยน
- reject delayed/stale events
- popup อ่านผลตาม tab ID และตรวจว่า URL/path ตรงกับ tab ปัจจุบัน

### 3.10 Website test pages

สร้าง test pages สำหรับ:

- safe page
- fake store
- fake bank
- gambling content only
- gambling plus data-leak behavior
- adult content only
- adult plus APK
- cross-domain login
- HTTP sensitive form
- benign modern SPA
- verified local network telemetry demo

`Website_testonly` เคยสร้างเป็น adversarial demo sites หลายแบบ จากนั้นผู้ใช้สั่งลบออกจาก Git แต่ local folder ยังมีอยู่

## 4. User Preferences ที่ต้องรักษา

### 4.1 Product/architecture preferences

- ใช้ local model ของ Project Argus เป็นหลัก
- ไม่ใช้ OpenAI หรือ external AI API อีก
- ไม่ใส่ API key ใน browser files หรือ repository
- ไม่ใช้ React
- ไม่เพิ่ม database ตอนนี้
- ไม่ทำ backend ใหญ่เกินความจำเป็น
- Chrome Extension ต้องทำงานได้แม้ backend ปิด
- raw dataset ใช้ train offline เท่านั้น ห้าม bundle เข้า extension/ZIP
- อย่า hardcode test websites เพื่อให้คะแนนผ่าน
- อย่าเพิ่มคะแนนแบบเหมารวมเพื่อแก้ test
- ต้องลด false positive บนเว็บปกติเป็นเป้าหมายสำคัญ
- เมื่อเปลี่ยน tab/page ต้องล้าง evidence เก่า
- ให้ระบบ observe สักระยะและดู network behavior ไม่ควรตัดสินทันทีจากภาพหรือข้อความอย่างเดียว

### 4.2 Risk priority ที่ผู้ใช้กำหนด

อันดับสูงสุด:

- confirmed sensitive data movement
- unencrypted sensitive write
- cross-domain sensitive write หลัง form/password/OTP interaction
- beacon/ping/query pixel หลัง sensitive interaction
- unsafe HTTP sensitive form
- evidence ที่บอกว่าข้อมูลไม่มี protection ระหว่าง transport

อันดับกลาง:

- password/OTP/login/account verification
- suspicious domain/URL structure
- HTTP page/form metadata
- script reading fields แล้วมี network sink
- dynamic endpoints, storage/cookie relay, WebSocket/postMessage relay
- phishing/fake bank/fake store/APK combinations

อันดับต่ำที่สุด:

- gambling category
- adult category
- รูปภาพเยอะ
- ads/popups เยอะ
- keyword/content category อย่างเดียว

เว็บพนันหรือเว็บโป๊อย่างเดียวควรเป็น SAFE หรือคะแนนต่ำมาก จนกว่าจะมีหลักฐานขโมยข้อมูลหรือ unsafe download/transport ที่ชัดเจน

### 4.3 UI preferences

- ใช้หน้าตาแบบ old/version 3
- badge อยู่มุมล่างซ้าย
- badge ต้องเล็ก ไม่บังเว็บ
- badge แสดง score พร้อม status
- คลิกแล้วค่อยเปิดรายละเอียด
- สี text และ border ต้องตรงกับระดับความเสี่ยง
- ห้ามมี popup เตือนด้านขวาบนอัตโนมัติ
- progressive observation ต้องไม่แสดงคะแนนเก่าระหว่าง `OBSERVING`
- demo mode ต้อง smooth และไม่ flicker

### 4.4 Working/communication preferences

- ผู้ใช้พูดไทยเป็นหลัก แต่รับ technical English ได้
- หลายครั้งผู้ใช้ต้องการให้ทำงานเงียบจนเสร็จ โดยเฉพาะงานยาว
- ถ้าผู้ใช้บอก `Don't say anything while working` หรือ `ไม่ต้องพูดระหว่างทำ` ต้องทำตาม
- ผู้ใช้ต้องการผลลัพธ์จริงมากกว่าแผนยาว
- เวลารายงานควรบอก: root cause, ไฟล์ที่แก้, test result, วิธี reload/test
- Push GitHub เฉพาะเมื่อผู้ใช้สั่งชัดเจน
- ก่อน push ต้องตรวจ secret, raw dataset, `.env`, venv, node_modules และ generated junk

## 5. สิ่งที่ทำงานแล้ว

- Manifest V3 และ Load unpacked structure
- content scanning และ modular analyzers
- local model artifact และ feature extraction
- evidence-first final decision path
- direct HTTP/cross-domain form detection
- Chrome `webRequest` metadata monitoring
- per-tab scan storage
- stale navigation guard
- popup dashboard และ Export Scan Report
- Options page
- Report False Positive local queue/collector
- old-style bottom-left badge/detail panel
- automatic top-right overlay ถูกปิด
- local FastAPI demo/static server
- ZIP/validation scripts
- safe-site, detector, policy, navigation และ privacy test suites

ผล test ล่าสุดหลังแก้ policy v2:

- Evidence policy: `13/13` passed
- Exfiltration pipeline regressions: `3/3` passed
- Policy integration: `788 SAFE cases`, `0 visible warnings`
- Direct-evidence validation: `236 HIGH_RISK cases` passed
- Safe-policy regressions: `14/14` passed
- Navigation isolation: `7/7` passed
- Detector regressions: `15/15` passed
- Core calibration: `200/200` passed
- Randomized evaluation: SAFE FP `0/500`, fake FN `0/500` ใน deterministic engine evaluation
- Manifest JSON และ JavaScript syntax checks ผ่าน

หมายเหตุ: synthetic/deterministic metrics ไม่ใช่ guarantee บน open web

## 6. สิ่งที่เคยไม่ทำงาน หรือทดลองแล้วไม่เหมาะ

### OpenAI classification

- เคยให้ 100/100 แทบทุกเว็บ
- prompt tuning อย่างเดียวแก้ hallucination/false positive ไม่พอ
- ถูกถอดออกตามคำสั่งผู้ใช้

### Category-heavy scoring

- เว็บพนัน เว็บโป๊ เว็บรูปเยอะ และเว็บโฆษณาเคยได้คะแนนสูงเกินไป
- ถูกลดเป็น weak context/content-only
- ห้ามนำ category กลับมาเป็น decision หลัก

### Immediate scoring

- เคยแสดงคะแนนก่อน observation จบ ทำให้ user สับสน
- ปัจจุบันมี preliminary/final phases และ UI ควรแสดง `OBSERVING` โดยไม่แสดงคะแนนเก่า

### คะแนน 60/100 ทุก tab

- เคยเกิดจาก static script groups เช่น dynamic endpoint/hidden credential frame ถูกใช้แรงเกินไป
- policy ถูกแก้ให้ static intent อย่างเดียวไม่สร้าง warning และ trusted pages มี guard

### คะแนน 5/100 ทุกเว็บ exfiltration

Root cause ที่พบล่าสุด:

- form event และ `webRequest` callback เป็นคนละ asynchronous channel
- บางครั้ง network request มาถึง service worker ก่อน sensitive form event
- request จึงไม่ถูก correlate กับ sensitive interaction
- policy เหลือเพียง static/model evidence และถูก cap แถว 5

การแก้ล่าสุด:

- เก็บ minimal request metadata ชั่วคราวใน observation window
- เมื่อ sensitive submit/focus event มาทีหลัง ให้ retroactively correlate request
- policy อ่าน service-worker-observed network counters เป็น direct evidence backstop
- ไม่เก็บ request body, full URL query, headers หรือ typed values
- เพิ่ม `scanResult.debug.pipeline`
- model-only/no behavior ถูกปรับให้แสดง `SAFE 0/100` แทน `UNCERTAIN 5/100`

สิ่งที่ยังต้องพิสูจน์บน Chrome จริง:

- screenshot ล่าสุดของผู้ใช้ยังเห็น 0/5 บนเว็บหลายเว็บ
- เว็บใน screenshot ส่วนใหญ่เป็น gambling/adult/ad-heavy/safe pages ที่ไม่มี sensitive form หรือ confirmed data movement ดังนั้นคะแนน 0/5 เป็น behavior ที่ตั้งใจไว้
- ต้องทดสอบกับหน้า `verified-network-exfil-demo.html` โดยกด submit และรอ interaction-final scan
- Chrome ต้อง Reload extension หลังแก้ source; unpacked extension ไม่ hot-reload เอง

### Real-browser automated harness

- `tests/run_real_browser_audit.js` เคยลองเปิด Chrome headless พร้อม unpacked extension
- การรันล่าสุด timeout เพราะไม่พบ extension service worker ใน headless context
- unit/integration tests ผ่าน แต่ real visible Chrome end-to-end ยังต้องตรวจเพิ่ม
- อย่าอ้างว่า browser E2E ผ่านจนกว่าจะรันบน actual loaded extension ได้จริง

## 7. Current Known Inconsistencies

Claude Code ควรแก้ documentation/version drift ต่อไปนี้อย่างระวัง:

- `manifest.json` เป็น `5.1.1`
- `package.json` ยังเป็น `5.1.0`
- `README.md` บางส่วนยังอธิบาย model-only เป็น `MONITORING/UNCERTAIN` แต่ policy ล่าสุดให้ no-evidence model-only เป็น `SAFE 0`
- `ARCHITECTURE.md` บางตำแหน่งยังเรียก Project Argus 4.2
- `tests/CALIBRATION_REPORT.md` เป็นรายงานยุค 4.2 และไม่ได้สะท้อน policy v2 ทั้งหมด
- Git remote ปัจจุบันคือ `Argus-Security.git` ไม่ใช่ชื่อ `Argus-Cybersecurity` ที่เคยพูดถึงในแชต
- latest changes ยังไม่ได้ push

## 8. Critical Files

- `manifest.json`: MV3 config และ version
- `content.js`: page metadata, form/password interaction, badge/detail UI
- `service_worker.js`: network telemetry, navigation state, analyzers/policy orchestration, storage
- `engine/argus_engine.js`: modular evidence analyzers
- `engine/evidence_decision_policy.js`: final visible decision authority
- `engine/navigation_session_guard.js`: stale-event protection
- `engine/feature_extractor.js`: 69 local model features
- `engine/trained_model.js` / `.json`: compact trained local model
- `engine/detection_policy.json`: weights, floors, caps
- `popup.js`: current-tab result, report export, false-positive reporting
- `style.css`: version-3-style badge/detail panel
- `backend/main.py`: optional local server and feedback collector; no OpenAI
- `scripts/train_full_mega_model.py`: full offline model training
- `scripts/validate.ps1`: release validation
- `scripts/build_zip.ps1`: ZIP packaging exclusions
- `tests/run_exfiltration_pipeline_regressions.js`: latest 0/5 bug regression
- `test-site/verified-network-exfil-demo.html`: local runtime network-correlation demo
- `scripts/serve_argus_test_site.js`: simple test server on port 4173

## 9. How To Run Current Version

### Load/reload extension

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked: `C:\Users\User\Desktop\Project-Argus-Extension`
4. หลังแก้ไฟล์ทุกครั้ง กด Reload บน Project Argus
5. ตรวจว่า card แสดง version `5.1.1`
6. Refresh tab ที่เปิดอยู่ เพื่อให้ content script ใหม่ถูก inject

### Run optional FastAPI backend

```powershell
cd C:\Users\User\Desktop\Project-Argus-Extension\backend
venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

Backend ไม่จำเป็นสำหรับการ scan; ใช้ serve test pages และรับ false-positive feedback

### Run verified telemetry demo

```powershell
cd C:\Users\User\Desktop\Project-Argus-Extension
node scripts\serve_argus_test_site.js
```

เปิด:

```text
http://127.0.0.1:4173/verified-network-exfil-demo.html
```

กด `Run local telemetry test`, รอประมาณ 5-6 วินาที แล้วตรวจ badge/detail panel

Expected:

- ก่อนกด: SAFE/low because no transfer has happened
- หลังกด: direct cross-domain sensitive write telemetry should become HIGH_RISK and exceed 5
- ถ้ายังเป็น 0/5 ให้ดู `scanResult.debug.pipeline`, network counters, accepted/rejected page events และ policy version

## 10. Test Commands

Focused tests:

```powershell
cd C:\Users\User\Desktop\Project-Argus-Extension
node tests\run_evidence_policy_tests.js
node tests\run_exfiltration_pipeline_regressions.js
node tests\run_policy_integration_tests.js
node tests\run_safe_policy_regressions.js
node tests\run_navigation_guard_tests.js
```

Full validation:

```powershell
node tests\run_detector_tests.js
node tests\run_exfiltration_calibration.js
node tests\run_benign_robustness.js
node tests\run_randomized_web_evaluation.js
node tests\run_randomized_cross_validation.js
node tests\run_model_training_tests.js
node tests\run_page_state_tests.js
node tests\run_report_privacy_tests.js
node tests\run_warning_path_audit.js
powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
```

ก่อน release/push ต้องเพิ่ม real Chrome manual QA ด้วย เพราะ headless harness ยังไม่ verified

## 11. Git/Release Rules

ก่อน commit/push:

- ตรวจ `git status --short`
- อย่าลบหรือ revert unrelated user changes
- ตรวจว่าไม่มี API key หรือ `.env`
- ห้าม include `backend/venv`
- ห้าม include `.git`, `node_modules`, `__pycache__`
- raw datasets ไม่ควรอยู่ใน submission ZIP หรือ Chrome runtime package
- reports/tmp/output ต้อง review ก่อน commit
- run validation suite
- rebuild ZIP
- push เฉพาะเมื่อผู้ใช้สั่ง

คำสั่ง ZIP:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_zip.ps1
```

## 12. What Claude Code Should Do Next

ลำดับแนะนำ:

1. อย่าเปลี่ยน architecture หรือ thresholds ทันที
2. Inspect dirty worktree และอ่าน latest policy/service-worker changes
3. Reload actual unpacked extension version `5.1.1`
4. Run verified telemetry demo ใน Chrome จริง
5. Export scan report หรืออ่าน `chrome.storage.local` เพื่อดู `debug.pipeline`
6. ตรวจว่า form event accepted, network write observed และ telemetry direct ID ถูกสร้าง
7. ถ้า demo ผ่าน แต่เว็บของผู้ใช้ยัง 0/5 ให้เปรียบเทียบ actual browser-observable behavior ไม่ใช่ category/รูปภาพ
8. ถ้า demo ไม่ผ่าน ให้แก้ event/network correlation หรือ Chrome permission/lifecycle โดยไม่เพิ่ม static score เหมารวม
9. รักษา model-only และ content-only protections
10. Sync README/package/architecture versions หลัง behavior final
11. Run full tests, rebuild ZIP และขออนุญาตก่อน push หากผู้ใช้ยังไม่ได้สั่ง

## 13. Non-Negotiable Safety/Quality Constraints

- ห้ามอ่านหรือเก็บ password/OTP/form values
- ห้ามเก็บ request/response body
- ห้ามเก็บ cookies, authorization headers หรือ private message contents
- ห้ามเรียก external AI service
- ห้ามทำให้ gambling/adult/image count เป็นเหตุ HIGH_RISK
- ห้าม hardcode domain ของ test site เพื่อบังคับ score
- ห้ามให้ model score เพียงอย่างเดียวสร้าง warning
- ห้ามใช้ stale evidence จาก navigation เก่า
- ห้ามอ้างว่า detection พิสูจน์ payload theft ถ้าเห็นเพียง metadata
- ควรแยกคำว่า static intent, correlated behavior และ confirmed network evidence ให้ชัดเจนใน UI/report

## 14. Short Summary For Claude Code

Project Argus ตอนนี้เป็น Chrome MV3 local evidence engine พร้อม local trained calibrator ขนาด 69 features. Final decision อยู่ที่ evidence policy ไม่ใช่ model. ผู้ใช้ให้ความสำคัญสูงสุดกับ browser-observed sensitive network behavior และต้องการ false positive ต่ำมาก. Gambling/adult/ads/images เป็น context ระดับต่ำเท่านั้น. UI ต้องเป็น badge เวอร์ชันเก่ามุมล่างซ้าย ไม่มี popup ด้านขวาบน. OpenAI ถูกลบแล้ว. บั๊กล่าสุดคือ exfiltration บางกรณีค้าง 5 เพราะ form event/network request race; มีการเพิ่ม retroactive correlation และ telemetry-direct policy backstop แล้ว แต่ต้องยืนยันบน actual Chrome หลัง Reload version 5.1.1. Working tree ล่าสุดยังไม่ได้ push และห้ามทำข้อมูลที่ยังไม่ commit หาย
