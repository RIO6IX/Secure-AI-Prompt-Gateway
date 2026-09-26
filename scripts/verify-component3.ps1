param(
    [string]$Python = "",
    [string]$Node = "node"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $Python) { $Python = Join-Path $projectRoot ".venv\Scripts\python.exe" }
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Create .venv and install python_gateway/requirements.txt first, or pass -Python with your interpreter path."
}
Push-Location $projectRoot
try {
    & $Python -m unittest discover -s python_gateway/tests -v
    if ($LASTEXITCODE -ne 0) { throw "Backend security tests failed" }
    & $Node node_modules/typescript/bin/tsc --noEmit
    if ($LASTEXITCODE -ne 0) { throw "TypeScript compilation failed" }
    & $Node --test tests/rendered-html.test.mjs
    if ($LASTEXITCODE -ne 0) { throw "Frontend regression checks failed" }
    & $Node node_modules/vinext/dist/cli.js build
    if ($LASTEXITCODE -ne 0) { throw "Production build failed" }
    Write-Output "Component 3 verification passed. No commits, pushes, or deployments were performed by this script."
}
finally {
    Pop-Location
}
