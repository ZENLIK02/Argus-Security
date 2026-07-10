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
    "tests/run_detector_tests.js"
  )

  foreach ($file in $javascriptFiles) {
    node --check $file
    if ($LASTEXITCODE -ne 0) { throw "JavaScript syntax check failed: $file" }
  }

  node tests/run_detector_tests.js
  if ($LASTEXITCODE -ne 0) { throw "Detector regression suite failed." }

  $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
  $pythonPath = if ($pythonCommand) { $pythonCommand.Source } else { Join-Path $project "backend/venv/Scripts/python.exe" }
  if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Python was not found. Install Python or create backend/venv first."
  }

  foreach ($file in @("manifest.json", "trusted_domains.json", "risky_categories.json", "engine/detection_policy.json")) {
    & $pythonPath -m json.tool $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "JSON validation failed: $file" }
  }

  & $pythonPath -m py_compile backend/main.py
  if ($LASTEXITCODE -ne 0) { throw "Python compile check failed: backend/main.py" }

  Write-Host "Project Argus validation passed." -ForegroundColor Green
} finally {
  Pop-Location
}
