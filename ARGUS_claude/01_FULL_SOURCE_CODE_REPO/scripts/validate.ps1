$ErrorActionPreference = "Stop"

$project = Split-Path -Parent $PSScriptRoot
Push-Location $project
try {
  $javascriptFiles = @(
    "content.js",
    "service_worker.js",
    "popup.js",
    "options.js",
    "engine/argus_engine.js",
    "engine/evidence_decision_policy.js",
    "engine/navigation_session_guard.js",
    "engine/feature_extractor.js",
    "engine/trained_model.js",
    "tests/run_detector_tests.js",
    "tests/run_exfiltration_calibration.js",
    "tests/run_model_training_tests.js",
    "tests/run_page_state_tests.js",
    "tests/run_benign_robustness.js",
    "tests/run_randomized_web_evaluation.js",
    "tests/run_randomized_cross_validation.js",
    "tests/run_evidence_policy_tests.js",
    "tests/run_safe_policy_regressions.js",
    "tests/run_policy_integration_tests.js",
    "tests/run_navigation_guard_tests.js",
    "tests/run_warning_path_audit.js",
    "tests/run_report_privacy_tests.js",
    "scripts/generate_exfiltration_corpus.js",
    "scripts/generate_benign_robustness_corpus.js",
    "scripts/generate_randomized_web_corpus.js",
    "scripts/train_local_model.js"
  )

  foreach ($file in $javascriptFiles) {
    node --check $file
    if ($LASTEXITCODE -ne 0) { throw "JavaScript syntax check failed: $file" }
  }

  node scripts/generate_exfiltration_corpus.js
  if ($LASTEXITCODE -ne 0) { throw "Corpus generation failed." }

  node scripts/generate_benign_robustness_corpus.js
  if ($LASTEXITCODE -ne 0) { throw "Benign robustness corpus generation failed." }

  node scripts/generate_randomized_web_corpus.js
  if ($LASTEXITCODE -ne 0) { throw "Randomized web corpus generation failed." }

  node tests/run_detector_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Detector regression suite failed." }

  node tests/run_exfiltration_calibration.js
  if ($LASTEXITCODE -ne 0) { throw "Exfiltration calibration suite failed." }

  $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
  $pythonPath = if ($pythonCommand) { $pythonCommand.Source } else { Join-Path $project "backend/venv/Scripts/python.exe" }
  if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Python was not found. Install Python or create backend/venv first."
  }

  node tests/run_model_training_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Local model training checks failed." }

  node tests/run_page_state_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Page-state isolation checks failed." }

  node tests/run_evidence_policy_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Evidence-first policy checks failed." }

  node tests/run_safe_policy_regressions.js
  if ($LASTEXITCODE -ne 0) { throw "Safe policy regression checks failed." }

  node tests/run_policy_integration_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Evidence policy integration checks failed." }

  node tests/run_navigation_guard_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Navigation session guard checks failed." }

  node tests/run_warning_path_audit.js
  if ($LASTEXITCODE -ne 0) { throw "Visible warning path audit failed." }

  node tests/run_report_privacy_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Report privacy audit failed." }

  node tests/run_benign_robustness.js
  if ($LASTEXITCODE -ne 0) { throw "Benign robustness suite failed." }

  node tests/run_randomized_web_evaluation.js
  if ($LASTEXITCODE -ne 0) { throw "Randomized real-vs-fake suite failed." }

  node tests/run_randomized_cross_validation.js
  if ($LASTEXITCODE -ne 0) { throw "Randomized five-fold cross-validation failed." }

  foreach ($file in @("manifest.json", "trusted_domains.json", "risky_categories.json", "engine/detection_policy.json", "engine/trained_model.json", "datasets/exfiltration_eval_cases.json", "datasets/benign_robustness_cases.json", "datasets/phiusiil_benign_cases.json", "datasets/phiusiil_balanced_url_seeds.json", "datasets/randomized_web_eval_cases.json", "tests/randomized_cv_report.json")) {
    & $pythonPath -m json.tool $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "JSON validation failed: $file" }
  }

  & $pythonPath -m py_compile backend/main.py
  if ($LASTEXITCODE -ne 0) { throw "Python compile check failed: backend/main.py" }

  & $pythonPath -m py_compile scripts/import_phiusiil_benign.py
  if ($LASTEXITCODE -ne 0) { throw "Python compile check failed: scripts/import_phiusiil_benign.py" }

  & $pythonPath -m py_compile scripts/import_phiusiil_balanced.py
  if ($LASTEXITCODE -ne 0) { throw "Python compile check failed: scripts/import_phiusiil_balanced.py" }

  & $pythonPath -m py_compile scripts/train_full_mega_model.py
  if ($LASTEXITCODE -ne 0) { throw "Python compile check failed: scripts/train_full_mega_model.py" }

  Write-Host "Project Argus validation passed." -ForegroundColor Green
} finally {
  Pop-Location
}
