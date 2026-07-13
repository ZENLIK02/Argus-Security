$ErrorActionPreference = "Stop"

$project = Split-Path -Parent $PSScriptRoot
Push-Location $project
try {
  $runs = 10
  for ($iteration = 1; $iteration -le $runs; $iteration += 1) {
    node tests/run_exfiltration_calibration.js *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "Calibration failed on stability run $iteration."
    }
    node tests/run_model_training_tests.js *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "Model checks failed on stability run $iteration."
    }
    node tests/run_benign_robustness.js *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "Benign robustness checks failed on stability run $iteration."
    }
    node tests/run_randomized_web_evaluation.js *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "Randomized real-vs-fake checks failed on stability run $iteration."
    }
    Write-Host "Stability run $iteration/$runs passed."
  }
  Write-Host "Project Argus passed all $runs repeated stability runs." -ForegroundColor Green
} finally {
  Pop-Location
}
