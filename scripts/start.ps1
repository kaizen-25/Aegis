# Starts the gateway and dashboard in their own windows. Close those windows to stop them.
#   -RealTools  start the gateway with AEGIS_TOOLS=real (workspace\ and outbox\ instead of the sandbox)
param([switch]$RealTools)
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'

if (-not (Test-Path $python)) {
    Write-Error 'No .venv found. Follow the setup steps in README.md first.'
    exit 1
}

$toolMode = if ($RealTools) { 'real' } else { 'simulated' }
Start-Process powershell -WorkingDirectory $root -ArgumentList @(
    '-NoExit', '-Command',
    "`$env:AEGIS_TOOLS='$toolMode'; & '$python' -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --log-level warning"
)
Start-Process powershell -WorkingDirectory (Join-Path $root 'dashboard') -ArgumentList @(
    '-NoExit', '-Command', 'npm run dev'
)

Write-Host "Gateway tools: $toolMode. Open http://127.0.0.1:5173"
