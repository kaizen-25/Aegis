# Real-tools split demo: the same poisoned task without Aegis, then with Aegis.
#
#   powershell -ExecutionPolicy Bypass -File scripts\demo_real.ps1 [-Task R1] [-ReviewWait 60] [-Seed 42]
#   Qwen3:  ... demo_real.ps1 -Model qwen3:8b -Think off -Task A08   (Qwen3 ignores R1 but follows A08)
#
# Starts a real-tools gateway (AEGIS_TOOLS=real) in its own window on port 8000 unless one is
# already running, then runs agent.real_demo. Needs Ollama with qwen2.5:7b-instruct-q4_K_M.
# Files: workspace\ (what the agent reads and writes), outbox\<mode>\ (the .eml files "sent").
param(
    [string]$Task = 'R1',
    [double]$ReviewWait = 0,
    [int]$Seed = 42,
    [double]$Temperature = 0,
    [string]$Model = 'qwen2.5:7b-instruct-q4_K_M',
    [ValidateSet('default', 'on', 'off')][string]$Think = 'default'
)

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
$gateway = 'http://127.0.0.1:8000'

if (-not (Test-Path $python)) {
    Write-Error 'No .venv found. Follow the setup steps in README.md first.'
    exit 1
}

function Get-Health {
    try { return Invoke-RestMethod "$gateway/health" -TimeoutSec 2 } catch { return $null }
}

$health = Get-Health
if ($null -eq $health) {
    Write-Host 'Starting a real-tools gateway in a new window...'
    Start-Process powershell -WorkingDirectory $root -ArgumentList @(
        '-NoExit', '-Command',
        "`$env:AEGIS_TOOLS='real'; & '$python' -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --log-level warning"
    )
    for ($i = 0; $i -lt 40 -and $null -eq $health; $i++) {
        Start-Sleep -Milliseconds 500
        $health = Get-Health
    }
    if ($null -eq $health) {
        Write-Error 'The gateway did not start. Check the new window for errors.'
        exit 1
    }
} elseif ($health.tool_mode -ne 'real') {
    Write-Error 'A gateway is already running on port 8000 in simulated mode. Close its window, then run this again.'
    exit 1
}

& $python -m agent.real_demo --task $Task --gateway $gateway --review-wait $ReviewWait --seed $Seed --temperature $Temperature --model $Model --think $Think
exit $LASTEXITCODE
