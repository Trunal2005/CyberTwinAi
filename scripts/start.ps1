param([switch]$Dev)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path '.venv\Scripts\python.exe')) { throw 'Run the README setup commands first.' }
if ($Dev) {
    Write-Host 'Run npm run dev from frontend in another terminal. API: http://127.0.0.1:8000'
    & '.\.venv\Scripts\python.exe' -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
} else {
    if (-not (Test-Path 'frontend\dist\index.html')) { throw 'Run npm run build in frontend first.' }
    & '.\.venv\Scripts\python.exe' -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
}
