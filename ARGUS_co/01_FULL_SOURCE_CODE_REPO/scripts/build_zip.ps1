$ErrorActionPreference = "Stop"

$project = Split-Path -Parent $PSScriptRoot
$desktop = [Environment]::GetFolderPath("Desktop")
$zip = Join-Path $desktop "Project-Argus-Extension.zip"
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("Project-Argus-Zip-" + [guid]::NewGuid().ToString())
$stageRoot = Join-Path $stage "Project-Argus-Extension"

try {
  New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

  $rootFiles = @(
    "manifest.json", "content.js", "service_worker.js", "popup.html", "popup.js",
    "options.html", "options.js", "style.css", "trusted_domains.json", "risky_categories.json",
    "README.md", "ARCHITECTURE.md", "PRIVACY_NOTES.md", "QA_TEST_PLAN.md", "RELEASE_CHECKLIST.md"
  )
  foreach ($file in $rootFiles) {
    Copy-Item -LiteralPath (Join-Path $project $file) -Destination $stageRoot
  }

  foreach ($directory in @("test-site", "engine")) {
    Copy-Item -LiteralPath (Join-Path $project $directory) -Destination $stageRoot -Recurse
  }

  $backendStage = Join-Path $stageRoot "backend"
  New-Item -ItemType Directory -Path $backendStage -Force | Out-Null
  foreach ($file in @("main.py", "requirements.txt", "README_BACKEND.md")) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $project "backend") $file) -Destination $backendStage
  }

  $stageRootFull = [System.IO.Path]::GetFullPath($stageRoot)
  $excludedDirectories = @("venv", "__pycache__", ".git", "node_modules", "Website_testonly")
  Get-ChildItem -LiteralPath $stageRoot -Directory -Recurse -Force |
    Where-Object { $excludedDirectories -contains $_.Name } |
    Sort-Object { $_.FullName.Length } -Descending |
    ForEach-Object {
      $candidate = [System.IO.Path]::GetFullPath($_.FullName)
      if (-not $candidate.StartsWith($stageRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe packaging exclusion path: $candidate"
      }
      Remove-Item -LiteralPath $candidate -Recurse -Force
    }
  Get-ChildItem -LiteralPath $stageRoot -File -Recurse -Force |
    Where-Object { $_.Name -eq ".env" -or $_.Name -match "\.(pyc|pyo)$" } |
    Remove-Item -Force

  if (Test-Path -LiteralPath $zip) {
    Remove-Item -LiteralPath $zip -Force
  }
  Compress-Archive -Path $stageRoot -DestinationPath $zip -Force
  Write-Host "Created $zip" -ForegroundColor Green
} finally {
  if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
  }
}
