"""Provision a disposable simulation database for the requested website recording."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'.cache/site-walkthrough'
WORK.mkdir(parents=True,exist_ok=True)
db=WORK/'simulation-demo.db'
if db.exists():
    print('Existing isolated recording database retained.');sys.exit(0)
credentials={'username':'demo_admin','password':secrets.token_urlsafe(24)}
(WORK/'credentials.json').write_text(json.dumps(credentials),encoding='utf-8')
os.environ.update(DATABASE_URL='sqlite:///'+db.as_posix(), FIREWALL_ADAPTER='simulated',REAL_ENFORCEMENT='false',
                  SURICATA_EVE_PATH='',SURICATA_LIVE_CONFIRMED='false',CORS_ORIGINS='http://127.0.0.1:8003')
subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True)
sys.path.insert(0,str(ROOT))
from backend.db import SessionLocal,User
from backend.security import password_hash
from backend.seed import seed_topology,seed_events
with SessionLocal() as session:
    session.add(User(username=credentials['username'],password_hash=password_hash(credentials['password']),role='admin'))
    session.commit();seed_topology(session);seed_events(session)
print('Isolated simulation database ready; normal application data untouched. Credentials are not displayed.')
