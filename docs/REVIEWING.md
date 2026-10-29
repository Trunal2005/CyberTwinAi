# Reviewing CyberTwin AI

Start with [the publication validation](PUBLICATION_VALIDATION.md), [CN technical result](CN_UPGRADE_RESULT.md), [upgrade validation](CN_UPGRADE_VALIDATION.md) and [professor practical/demo script](CN_PRACTICAL.md). This publication includes the CN upgrade, database migration 0003, updated media and recent traffic/Settings fixes.

## Run a fresh clone

Follow the root README in order: clone, install pinned Python dependencies, copy `.env.example`, set your own administrator credentials, migrate, create the administrator, seed, train, install frontend dependencies and build. Then start the server and open http://127.0.0.1:8000. Use the credentials you chose; no account or password is shipped.

Python 3.13 and Node 20.19+ or 22 are the documented versions. SQLite is the default and needs no separate database server. Docker is optional. Keep the process running while reviewing the UI. `localhost` and `127.0.0.1` are different cookie hosts; use one consistently.

## Suggested review order

1. Read the README architecture, scoring formulas and limitations.
2. Review `backend/security.py`, `schemas.py` and `main.py` for authentication, validation, confirmation and API access checks.
3. Review `detection.py` and `firewall.py` for event provenance, exclusions, expiry and simulated enforcement. Default simulation never changes the host firewall.
4. Review `ml.py` and `twin.py` for synthetic evaluation and modeled graph assumptions.
5. Review `db.py`, Alembic migrations and `frontend/src/` for persistence and the ten API-connected pages, including PCAP & Traffic Analysis.
6. Run the automated checks below and the demonstration steps in the README. Import the included `samples/` files as replay data.

## Automated checks

From the root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
Set-Location frontend
npm test
npm run build
Set-Location ..
```

On Linux/macOS, use `.venv/bin/python` for the Python command. Tests use isolated fixtures and a simulated adapter. With your local server running and `.env` matching the provisioned account, run `python scripts/smoke.py` using the virtual environment. It logs in, checks read APIs, exports reports and logs out. Review `docs/VALIDATION.md` for dated results and untested integrations.

## Included assets and exclusions

The repository includes source, lockfiles, migrations, examples, tests, Docker configuration, API schema, screenshots, the A3 poster and the updated 12:45 Hindi/Hinglish actual-site walkthrough. The earlier site and slide videos are retained as archives. Media is optional for running the application.

Local `.env`, accounts, databases, session records, trained joblib artifacts, node_modules, virtual environments, caches, temporary rendering drafts and build output are excluded. Setup regenerates the database, model and frontend bundle. An unrelated Business Intelligence report is excluded from this CyberTwin repository.

## Current video and poster

Watch [the local chapter player](http://127.0.0.1:8000/walkthrough/cn-demo.html) after starting the app. The [video README](../deliverables/video/README.md) links the MP4, transcript, subtitles and validation. The viewer uses a WebM fallback when H.264/AAC is unavailable. The [poster](../deliverables/poster/CyberTwin_AI_A3_Project_Poster.pdf) is one A3 portrait page.

The current video uses offline Piper Hindi narration; no project narration is sent to a service. See [offline reproduction and voice credits](../deliverables/video/CN_VIDEO_README.md). Watching the supplied files requires no TTS or recording tools.

## Archived recording tools

The commands below reproduce the older, archived pre-CN video and use online Google TTS. They are not required to run the app or watch/reproduce the current offline-narrated video. Run them only if you explicitly choose that online narration service:

```powershell
Set-Location tools/video
npm ci
npx playwright install chromium
Set-Location ../..
.\.venv\Scripts\python.exe -m pip install --target .cache/video-deps gTTS==2.5.4 imageio-ffmpeg==0.6.0
.\.venv\Scripts\python.exe scripts/prepare_site_demo.py
.\.venv\Scripts\python.exe scripts/narrate_site_demo.py
node scripts/record_site_demo.mjs
.\.venv\Scripts\python.exe scripts/encode_site_demo.py
.\.venv\Scripts\python.exe scripts/publish_site_walkthrough.py
```

The recorder uses port 8003 and a separate disposable simulation database. Narration generation uses online Google TTS. Encoding expects the Windows Nirmala UI font; archived slide-generation scripts also use Windows fonts. These optional media tools are not application requirements. `CYBERTWIN_PYTHON` can override the recorder's virtual-environment interpreter.
