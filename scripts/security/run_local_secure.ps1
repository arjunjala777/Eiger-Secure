param(
    [ValidateRange(1024, 65535)][int]$AppPort = 8000,
    [ValidateRange(1024, 65535)][int]$CorePort = 9001,
    [ValidateRange(1024, 65535)][int]$CrmPort = 9002,
    [ValidateRange(1024, 65535)][int]$GatewayPort = 11435
)
$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $Repo ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Project virtual environment not found. Run 'uv sync --extra blue-team' first."
}

function New-Secret {
    param([int]$Bytes = 48)
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buffer).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

$RequiredPorts = @($AppPort, $CorePort, $CrmPort, $GatewayPort)
if (@($RequiredPorts | Sort-Object -Unique).Count -ne 4) {
    throw "Each service requires a distinct port."
}
$Busy = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $RequiredPorts -contains $_.LocalPort } |
    ForEach-Object { $_.LocalPort } | Sort-Object -Unique)
if ($Busy.Count -gt 0) {
    throw "Secure stack ports are already occupied: $($Busy -join ', '). Stop the old Eiger services first."
}
$Ollama = Get-NetTCPConnection -State Listen -LocalPort 11434 -ErrorAction SilentlyContinue
if (-not $Ollama -or @($Ollama | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') }).Count -gt 0) {
    throw "Ollama must be running on loopback only (127.0.0.1:11434) before starting Eiger."
}

$env:HALCYON_MODE = "secure"
$env:HALCYON_PROFILE = "lab"
$env:HALCYON_LOCK_SECURITY_LEVELS = "true"
$env:HALCYON_SESSION_SECRET = New-Secret
$env:HALCYON_MCP_CORE_TOKEN = New-Secret
$env:HALCYON_MCP_CRM_TOKEN = New-Secret
$env:HALCYON_MCP_CORE_DELEGATION_SECRET = New-Secret
$env:HALCYON_MCP_CRM_DELEGATION_SECRET = New-Secret
$env:EIGER_OLLAMA_GATEWAY_TOKEN = New-Secret
$env:EIGER_APP_PORT = "$AppPort"
$env:EIGER_APP_URL = "http://127.0.0.1:$AppPort"
$env:EIGER_ALLOWED_ORIGINS = "http://localhost:$AppPort"
$env:OLLAMA_UPSTREAM_URL = "http://127.0.0.1:11434"
if (-not $env:EIGER_MODEL_MANIFEST) {
    $env:EIGER_MODEL_MANIFEST = Join-Path $Repo "config\models.json"
}
if (-not (Test-Path -LiteralPath $env:EIGER_MODEL_MANIFEST)) {
    throw "A reviewed model digest manifest is required at EIGER_MODEL_MANIFEST. Do not automatically trust the current Ollama inventory."
}
$env:OLLAMA_URL = "http://127.0.0.1:$GatewayPort"
$env:EIGER_TRUSTED_OLLAMA_URL = $env:OLLAMA_URL
$env:OLLAMA_MODEL = "llama3.1:8b"
$env:LLAMA_GUARD_MODEL = "llama-guard3:1b"
$env:EIGER_OLLAMA_MODELS = "llama3.1:8b,llama-guard3:1b"
$env:MCP_CORE_URL = "http://127.0.0.1:$CorePort/mcp"
$env:MCP_CRM_URL = "http://127.0.0.1:$CrmPort/mcp"
$env:EIGER_KB_PATH = Join-Path $Repo "data\eiger-kb.sqlite3"
$env:EIGER_GUARD_MODE = "observe"

$LogDir = Join-Path $Repo "logs"
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
$Processes = @()
$StartupComplete = $false
try {
    $Processes += Start-Process -FilePath $Python -ArgumentList @("-m", "uvicorn", "halcyon.ollama_gateway:app", "--host", "127.0.0.1", "--port", "$GatewayPort") -WorkingDirectory $Repo -RedirectStandardOutput (Join-Path $LogDir "ollama-gateway.out.log") -RedirectStandardError (Join-Path $LogDir "ollama-gateway.err.log") -WindowStyle Hidden -PassThru
    $Processes += Start-Process -FilePath $Python -ArgumentList @("-m", "uvicorn", "halcyon.mcp_deploy:CORE_ASGI", "--host", "127.0.0.1", "--port", "$CorePort") -WorkingDirectory $Repo -RedirectStandardOutput (Join-Path $LogDir "mcp-core.out.log") -RedirectStandardError (Join-Path $LogDir "mcp-core.err.log") -WindowStyle Hidden -PassThru
    $Processes += Start-Process -FilePath $Python -ArgumentList @("-m", "uvicorn", "halcyon.mcp_deploy:CRM_ASGI", "--host", "127.0.0.1", "--port", "$CrmPort") -WorkingDirectory $Repo -RedirectStandardOutput (Join-Path $LogDir "mcp-crm.out.log") -RedirectStandardError (Join-Path $LogDir "mcp-crm.err.log") -WindowStyle Hidden -PassThru

    $Deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 400
        try {
            Invoke-RestMethod -Uri "$env:OLLAMA_URL/api/tags" -Headers @{ Authorization = "Bearer $env:EIGER_OLLAMA_GATEWAY_TOKEN" } -TimeoutSec 2 | Out-Null
            $GatewayReady = $true
        } catch { $GatewayReady = $false }
    } while (-not $GatewayReady -and (Get-Date) -lt $Deadline)
    if (-not $GatewayReady) { throw "Inference gateway did not become ready; inspect logs/ollama-gateway.err.log." }

    $Runner = '"{0}"' -f (Join-Path $Repo "run_eiger.py")
    $Processes += Start-Process -FilePath $Python -ArgumentList $Runner -WorkingDirectory $Repo -RedirectStandardOutput (Join-Path $LogDir "eiger.out.log") -RedirectStandardError (Join-Path $LogDir "eiger.err.log") -WindowStyle Hidden -PassThru
    # Cold NeMo/model imports can exceed 45 seconds on the local workstation.
    $Deadline = (Get-Date).AddSeconds(120)
    do {
        Start-Sleep -Milliseconds 500
        try {
            Invoke-RestMethod -Uri "$env:EIGER_APP_URL/health" -TimeoutSec 3 | Out-Null
            $AppReady = $true
        } catch { $AppReady = $false }
    } while (-not $AppReady -and (Get-Date) -lt $Deadline)
    if (-not $AppReady) { throw "Eiger did not become ready; inspect logs/eiger.err.log." }
    & $Python (Join-Path $Repo "scripts\security\live_secure_probe.py")
    if ($LASTEXITCODE -ne 0) { throw "Secure Lab live probes failed." }
    $StartupComplete = $true
    Write-Output "Secure Lab started on http://localhost:$AppPort. Runtime credentials are ephemeral and were not written to disk."
    Write-Output "Services remain running independently. Stop their uvicorn process IDs to shut down the stack; Ollama remains running."
} finally {
    if (-not $StartupComplete) {
        foreach ($Process in $Processes) {
            if ($Process -and -not $Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
