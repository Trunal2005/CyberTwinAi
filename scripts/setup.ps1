param([switch]$SkipInstall)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) { throw 'Stop the local server on port 8000 before setup or migration. Existing data will not be touched.' }
function Run-Python { & '.\.venv\Scripts\python.exe' @args; if ($LASTEXITCODE -ne 0) { throw 'Python setup step failed. See the error above.' } }
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    if (Get-Command uv -ErrorAction SilentlyContinue) { uv --cache-dir .cache/uv venv .venv --python 3.13 }
    else { python -m venv .venv }
    if ($LASTEXITCODE -ne 0) { throw 'Could not create Python 3.13 virtual environment.' }
}
if (-not $SkipInstall) {
    if (Get-Command uv -ErrorAction SilentlyContinue) { uv --cache-dir .cache/uv pip install --python .venv/Scripts/python.exe -r requirements.txt -c requirements.lock.txt }
    else { Run-Python -m pip install -r requirements.txt -c requirements.lock.txt }
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}
if (-not (Test-Path '.env')) {
    Copy-Item .env.example .env
    Write-Host 'Created .env. Set ADMIN_USERNAME and a unique ADMIN_PASSWORD of at least 12 characters, then rerun this script.'
    return
}
Write-Host 'Stop the application server before migrating an existing database. Existing accounts and data are preserved.'
Run-Python scripts/backup_database.py
Run-Python -m alembic upgrade head
Run-Python -c "from backend.db import SessionLocal,User; from backend.manage import create_admin; from sqlalchemy import select; db=SessionLocal(); exists=db.scalar(select(User)); db.close(); print('Existing accounts preserved') if exists else create_admin()"
Run-Python -m backend.seed --extend-network
Run-Python -c "from backend import ml; bundle=ml.load(); ml.train() if not bundle or bundle['metrics'].get('feature_schema','synthetic-v1')=='synthetic-v1' else print('Existing research model preserved; use a separate MODEL_PATH for the synthetic demo')"
Run-Python scripts/generate_cn_capture.py
Push-Location frontend
try { if (-not $SkipInstall) { npm ci; if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' } }; npm run build; if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' } } finally { Pop-Location }
Write-Host 'Setup complete. Start with .\scripts\start.ps1 and open http://127.0.0.1:8000.'
