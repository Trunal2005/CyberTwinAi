# CyberTwin AI

A working, local research platform for intrusion detection, controlled prevention, source-IP investigation, and graph-based defense simulation. React + TypeScript + Vite + Tailwind, FastAPI + Pydantic + SQLAlchemy, SQLite, NetworkX, Pandas, and scikit-learn. All ten workspace pages use authenticated APIs and persisted records.

## Start reviewing

- **Run the application:** follow the Windows or Linux/macOS setup below. A fresh clone creates its own database, administrator account, model and frontend build.
- **Review the CN workflow:** [professor practical](docs/CN_PRACTICAL.md), [reviewer guide](docs/REVIEWING.md), [research-data workflow](docs/RESEARCH_DATA.md).
- **Presentation poster:** [A3 project poster](deliverables/poster/CyberTwin_AI_A3_Project_Poster.pdf).
- **Actual-site Hinglish video:** [download MP4](deliverables/video/CyberTwin-AI-CN-Site-Explanation-Hinglish.mp4), 12:45 / 16 chapters. With the server running, open [the video player](http://127.0.0.1:8000/walkthrough/cn-demo.html). It includes a WebM browser fallback, transcript and subtitles; all narration was generated locally.
- **Validation:** [publication checks](docs/PUBLICATION_VALIDATION.md) and the [CN upgrade record](docs/CN_UPGRADE_VALIDATION.md). GitHub Actions runs backend, frontend and browser checks on pushes.

**Default: SIMULATION, monitoring stopped, detection-only, simulated firewall.** No startup command changes the host firewall. Seeded/generated observations are labeled simulation; every uploaded log is replay. A fresh, explicitly configured server-owned Suricata EVE source is required for live observations. Observed IPs are not proof of identity.


## Computer Networks upgrade

Completed upgrade evidence: [technical result and exact file manifest](docs/CN_UPGRADE_RESULT.md), [final test report](docs/CN_UPGRADE_VALIDATION.md), and [reviewed observed-network screenshot](docs/screenshots/cn-observed-network.png).

Start with [the practical explanation and professor demo](docs/CN_PRACTICAL.md), [upgrade audit](docs/CN_UPGRADE_AUDIT.md) and [local real-dataset research workflow](docs/RESEARCH_DATA.md). PCAP and Traffic Analysis now connects normalized flows, original evidence, IDS findings, explicit prevention decisions and observed endpoint overlays on the existing virtual network. Observed edges and modeled paths are labeled separately.

Existing installations: stop the server, install updated pinned dependencies, back up the SQLite database, then run migration 0003. No historical measurement is invented; existing event records remain intact. Run:

```powershell
# After creating .env as described below; preserves existing accounts.
.\scripts\setup.ps1
.\scripts\start.ps1
```

The setup script backs up existing SQLite data to ignored `.cache/backups/`, migrates, preserves accounts, seeds missing data, explicitly extends the virtual CN model, retrains the synthetic benchmark and builds the frontend. It does not enable monitoring or enforcement. If .env is absent it creates the template and asks you to edit credentials before rerunning. PostgreSQL users must back up with their database tools and use the manual migration steps.

Upload `samples/cn-demo.pcap` or `.pcapng` on PCAP and Traffic Analysis. These are deterministic, owned header-only lab examples, generated without sending traffic by `python scripts/generate_cn_capture.py`. No Npcap, cloud service, administrator privileges or Linux installation is required for replay. Files are bounded to 2 MB; captures to 10,000 packets/1,000 conversations. Offline imports are always REPLAY.

Open Network Digital Twin → Observed traffic to replay stored endpoint observations, inspect flows and action timelines, save virtual positions and edit service permissions. The existing what-if workbench remains available. Real Linux firewall packet dropping is **NOT VERIFIED** here; the optional namespace-only procedure is in [LAB.md](docs/LAB.md). Archived video artifacts describe the earlier UI and are not evidence that the upgrade's live/kernel features were exercised.

## Quick start (Windows PowerShell)

Use Python 3.13 and Node 20.19+ or Node 22. From the project directory:

```powershell
git clone https://github.com/Trunal2005/CyberTwinAi.git
Set-Location CyberTwinAi
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -c requirements.lock.txt
Copy-Item .env.example .env
```

If Windows `ensurepip` or its temporary directory fails, use the alternative below (uv must already be installed):

```powershell
uv --cache-dir .cache/uv venv .venv --python 3.13
uv --cache-dir .cache/uv pip install --python .venv/Scripts/python.exe -r requirements.txt -c requirements.lock.txt
```

Edit `.env`: choose `ADMIN_USERNAME` and a unique `ADMIN_PASSWORD` with at least 12 characters. No default credentials are in source. Do not commit this file. Environment variables override `.env`. Keep `COOKIE_SECURE=false` only for loopback HTTP; use `true` behind HTTPS.

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m backend.manage create-admin
.\.venv\Scripts\python.exe -m backend.seed --extend-network
.\.venv\Scripts\python.exe -m backend.ml
Set-Location frontend
npm ci
npm run build
Set-Location ..
.\scripts\start.ps1
```

Open [CyberTwin](http://127.0.0.1:8000) and sign in. The built frontend and API share one origin. Swagger: [API documentation](http://127.0.0.1:8000/docs); OpenAPI: [schema](http://127.0.0.1:8000/openapi.json). The script binds loopback. Keep one Uvicorn worker: the collector, action mutex, and rate limiter are process-local.

Each clone starts without accounts, a database or model artifacts. Run every setup step above and sign in with the credentials you set in your own `.env`. Seeding creates 48 labeled simulation events; training creates the local synthetic model. There is no shared default password.

For a structured code review, see [the reviewer guide](docs/REVIEWING.md). Preview the upgraded [traffic analysis](docs/screenshots/cn-traffic-analysis.png), [linked flow evidence](docs/screenshots/cn-flow-journey.png) and [observed network](docs/screenshots/cn-observed-network.png). After starting the app, watch the [actual-site Hinglish walkthrough](http://127.0.0.1:8000/walkthrough/cn-demo.html); its MP4, WebM, captions and transcript are included in `deliverables/video/`.

For frontend development, run `scripts/start.ps1 -Dev`, then run `npm run dev` in `frontend` in a second terminal and open [Vite](http://127.0.0.1:5173). Its `/api` proxy targets port 8000. The production backend must be restarted after the first build so it mounts `dist`.

## Linux / macOS

```sh
git clone https://github.com/Trunal2005/CyberTwinAi.git
cd CyberTwinAi
python3.13 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -c requirements.lock.txt
cp .env.example .env
# Set your administrator credentials in .env before proceeding.
python -m alembic upgrade head
python -m backend.manage create-admin
python -m backend.seed --extend-network
python -m backend.ml
cd frontend && npm ci && npm run build && cd ..
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Direct dependencies are pinned; npm also includes a transitive lockfile. Python's fully resolved environment can be captured using `uv pip freeze --python .venv/Scripts/python.exe > requirements.lock.txt`. Re-run validation when changing package versions.

The checked-in lockfile constrains installation to the validated Python environment. See `docs/openapi.json` for an offline API snapshot and `docs/screenshots/` for desktop/mobile previews.

## Demonstration walkthrough

1. **Overview:** review stored counts, event-origin totals, timeline, severity, sources and mean rule-risk trend. Network health is explicitly unmeasured. Timeline/source analytics use the latest 10,000 events; KPI counts use all stored events.
2. **Live Monitoring:** start the simulated stream (one generated event every three seconds), stop it, import `samples/events.json`, `samples/events.csv`, or `samples/eve.jsonl`. All uploads are REPLAY. No packets are sent or scanned.
3. **Threat Detection:** filter/search/sort/page alerts, open an event, review evidence, mark investigating/resolved/false_positive, or investigate its observed source.
4. **IP Investigation:** inspect target services, first/last seen, protocols/ports, virtual device matches, blocks and event history; save analyst notes or export an IP-scoped JSON report. History is bounded to 1,000 events; first/last and count cover all matches.
5. **Settings → Enforcement:** preview and confirm manual approval. **Blocklist:** enter `192.0.2.44`, supply a reason, preview and confirm a temporary simulated block; then remove it. Record says `simulated`, never verified real enforcement. Expiry runs every three seconds and on reads. Automatic mode uses rule risk, threshold and a ten-actions/minute budget, with every exclusion audited.
6. **Network Digital Twin:** select the web server as initial compromise. Run baseline. Restrict the direct web→database link and patch the application server; rerun and compare. Click assets, edit vulnerability/criticality, add/remove devices/connections, edit baseline access rules, or isolate a virtual workstation. Saved comparisons persist snapshots.
7. **AI Insights:** inspect actual synthetic test metrics, confusion matrix, baseline and feature importance. Change a flow and request a persisted model prediction. If the model file is removed, the API says unavailable and rule detection continues.
8. **Reports:** export JSON, CSV, PDF, or print. JSON/PDF include evidence, actions, false-positive review count, latest twin comparison and ML evaluation. CSV is the event table. The report snapshot is bounded to the latest 10,000 matching events and 200 audit entries.

## Architecture

```mermaid
flowchart LR
  UI[React operations workspace] -->|HttpOnly session cookie| API[FastAPI / OpenAPI]
  API --> DB[(SQLAlchemy: SQLite / PostgreSQL)]
  Test[Generated test events: simulation] --> IDS[Validated detection pipeline]
  Upload[JSON / CSV / EVE import: replay] --> IDS
  EVE[Explicit server EVE collector: fresh live records] --> IDS
  IDS --> Rules[Authentication / scan / rate / burst / engine rules]
  IDS --> ML[Persisted synthetic Random Forest]
  Rules --> Decision[Policy / threshold / protected IP / rate limit]
  ML --> DB
  Decision --> Sim[Simulated adapter: default]
  Decision --> NFT[Explicitly configured Linux nftables lab]
  Rules --> DB
  Sim --> Audit[Persisted action intent and audit]
  NFT --> Audit
  Audit --> DB
  API --> Twin[NetworkX reachability and what-if analysis]
  Twin --> DB
  DB --> Reports[JSON / CSV / PDF]
```

`backend/` contains the API, models, schemas, authentication, detection, adapters, ML and graph services. `frontend/src/` contains the operations workspace and reusable components. `migrations/` is Alembic with a frozen v1 schema snapshot. `tests/` covers security and domain behavior; `samples/` contains bounded import examples.

## IDS vs IPS and scoring

**IDS** observes and flags events; it does not stop traffic. Implemented rules: `AUTH-001` ≥5 reported failed authentications; `SCAN-001` ≥8 distinct destination ports from the same source in a 60-second event-time window; `RATE-001` ≥100 reported/observed connections/minute; `BURST-001` >10 MB in <10 seconds; `ENGINE-SIGNATURE` maps a supplied signature severity. Origin-specific history prevents simulation/replay/live mixing. Observations beyond the correlation history cap (1,000) or arriving out of order may be incompletely correlated. Imported signatures are untrusted replay evidence.

Rule risk: authentication `min(95,60+2*failures)`, port diversity 78, rate 80, burst 65, signature severity 1/2/3 → 95/75/45. The maximum matching score is used. Severity: critical ≥90, high ≥70, medium ≥40, otherwise low. Evidence retains all matched conditions; the displayed primary rule follows the last matching rule. A low score is not proof of safety. This bounded rule set cannot detect every attack.

**IPS** makes a separate enforcement decision: authenticated administrator or qualifying detection → valid unicast IP → policy threshold → protected CIDRs/allowlist/local host checks → rate budget → selected adapter → verification/audit. Detection-only refuses new blocks. Manual mode requires explicit confirmation. Automatic mode runs only after an administrator previews and confirms policy. Turning detection-only on does not remove existing blocks; remove them or let them expire.

**ML score** is a synthetic model's uncalibrated probability, displayed independently. It never alone triggers enforcement. Model confidence is max(p,1-p), not a guarantee. Missing observed features stay unavailable. Versioned model bundles can apply explicitly disclosed training-partition mean imputation; predictions identify every missing and imputed feature. Legacy artifacts without imputation metadata refuse incompatible input. Source adapters do not fabricate authentication/frequency values.

**Twin risk** = `100 × Σ(reachable criticality × vulnerability) / Σ(all criticality × 10)`. Scores are illustrative normalized model units. Critical assets have criticality ≥4. Access edges are directed. Patching sets vulnerability to zero and prevents onward traversal from that pivot, except the initially compromised node. This simplified assumption does not establish real exploitability. Isolated nodes lose inbound/outbound edges. Enumeration is capped at 500 simple paths and 8 hops; reachability itself is complete. A truncated path count is a lower bound. Operational cost displays counts of changed links/devices, not invented downtime or savings.

## Authentication and security design

- PBKDF2-HMAC-SHA256 passwords with per-user random salts, 600,000 iterations and constant-time comparisons. No plaintext password in DB.
- Random 48-byte opaque session token in an HttpOnly, SameSite=Strict cookie; only SHA256 token hashes persist. Sessions expire after eight hours; logout revokes one, password reset revokes all.
- `python -m backend.manage reset-password` uses the same administrator environment variables. Remove provisioning credentials from the server environment after account creation if desired.
- Every data and mutation API requires an admin role. Only `/api/health`, static frontend, and API schema/docs are public; docs contain no application data. There is no anonymous enforcement endpoint or arbitrary command execution API.
- Browser origin and cross-site mutation checks plus SameSite cookies mitigate CSRF. CORS is an explicit environment list. Use loopback only for HTTP; require TLS + secure cookies for a network deployment. Do not wildcard credentialed CORS.
- Login (5/min/IP), ingestion, imports, policy, graph and enforcement operations have in-process rate limits. Mutation input uses Pydantic validation. Audit includes login failures, policy, enforcement, reviews, notes and topology modifications.
- Imports are read at most 2 MB, capped at 1,000 records, validated as a complete batch before ingestion, and not saved or executed. Filenames are never filesystem paths. CSV exports neutralize formula prefixes. Model files are server-owned; never load an untrusted joblib file.
- The simulated adapter never runs a command. nftables uses validated canonical addresses and fixed argument arrays with `shell=False`; no request selects an executable, table, chain or command. Host management, localhost, loopback, multicast, link-local, reserved addresses, allowlists and configured trusted networks are excluded.
- External action intent is committed before side effects. Failed/uncertain operations remain `pending`/`error` for reconciliation. nftables has kernel TTLs; DB expiration alone is never used to enforce a real block's lifetime. All removals preserve history.

## Suricata and real enforcement

Read [the isolated lab guide](docs/LAB.md) before configuring a real source or adapter. Suricata is an external sensor, not installed or started by CyberTwin. EVE file parsing is implemented; offline Zeek JSON conn.log replay is supported while its live collector remains unconfigured. Live status requires explicit `SURICATA_LIVE_CONFIRMED=true`, a server-owned readable path, active collection and a valid record timestamp within 90 seconds (at most 5 seconds in the future). Stale records encountered after rotation are REPLAY. Start from EOF; stopped collectors cannot remain live. Log freshness verifies ingestion, not independent proof that the sensor's selected interface captures all network traffic.

Real adapter implementation targets Linux nftables only and is unavailable on Windows. Simulation and uploaded/replayed events can never produce real blocks. Real blocks additionally require a source-matching live observation from the preceding ten minutes. `IPS ENFORCEMENT ENABLED` requires explicitly configured adapter, readable sets/rules and a non-detection policy; it says the enforcement mechanism is enabled, not that any specific packet was dropped. An individual `verified` block confirms set membership, not end-to-end packet delivery measurements.

## Reproducible ML / research methodology

`python -m backend.ml` generates 2,400 independent synthetic flows with seed 42. Features: duration, packets, bytes, frequency, failed authentications, criticality, destination port. A stochastic probability generator uses frequency, failed authentications and packet counts with overlap; labels are sampled, not copied from rule outputs. There are no source identifiers, severity/risk outputs or labels in the features. Split is stratified 75/25 before fitting. Candidate is a 120-tree Random Forest (depth 8, minimum leaf 8); baseline predicts the most frequent class. No preprocessing is fitted on test data. Model and JSON report persist in `data/`, and metadata persists in DB.

The current held-out synthetic run has 600 test rows, confusion matrix `[[244,65],[74,217]]`, suspicious precision 0.770, recall 0.746, F1 0.757, and false-positive rate 0.210. These come from running the script, not dashboard constants. UI always fetches the loaded artifact's actual report. Synthetic row independence is useful for smoke tests, not external validity.

For a college study: state the authorized lab and threat model; compare IDS rules, majority baseline and RF on the same ground truth; report precision/recall/F1 and false positives with class balance; evaluate held-out hosts/sessions/time periods in any real dataset; fit preprocessing only on training partitions; keep tuning separate from the final test; report calibration, repeated-seed confidence intervals, dataset provenance/license, leakage checks, missed detections and latency. Compare twin defenses using fixed baseline snapshots and publish the formula/assumptions. Have humans review false positives. Never infer an improvement in actual network safety from synthetic metrics alone. The default `backend.ml` command trains the included synthetic benchmark. An optional local CSV evaluator, `backend.research_ml`, compares majority, logistic-regression and Random Forest models using group-disjoint splits; see [RESEARCH_DATA.md](docs/RESEARCH_DATA.md). No published real dataset is bundled, downloaded or claimed as evaluated here.

Primary references: [Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html), [scikit-learn common pitfalls](https://scikit-learn.org/stable/common_pitfalls.html), [Random Forest reference](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html).

## Database, migrations and PostgreSQL

`python -m alembic upgrade head` initializes users/sessions, events, devices/connections/access rules, block records, enforcement/audit logs, notes, scenarios, model metadata and settings. UTC timestamps are normalized on ingestion and restored as UTC for SQLite comparisons; JSON serialization keeps event provenance. Source/destination IP, event timestamp, severity, origin, block state/expiry and connection endpoints are indexed. Unique usernames/device IPs, primary keys and foreign keys constrain records. Future migrations should use Alembic operations and a new revision, never edit `schema_v1.py`.

SQLite default is `data/cybertwin.db`. Back up the DB and model together while the server is stopped. For PostgreSQL, provision a private database and set `DATABASE_URL=postgresql+psycopg://USER:PASSWORD@localhost/cybertwin`, then run the same migrations/provision/seed/train commands. The driver is included. URL-escape special password characters. Moving existing SQLite data requires an explicit reviewed ETL/backup plan; changing the URL initializes a different database and does not migrate records. PostgreSQL support is configured via SQLAlchemy but not integration-tested here.

## Docker (optional)

The image runs an unprivileged user and includes built frontend and API. Compose binds only loopback and persists SQLite in a named volume. Create `.env` as above, then:

```sh
docker compose build
docker compose run --rm app python -m alembic upgrade head
docker compose run --rm app python -m backend.manage create-admin
docker compose run --rm app python -m backend.seed --extend-network
docker compose run --rm app python -m backend.ml
docker compose up
```

The container is always simulated, has no added network capabilities, and is not a host-firewall control container. Compose/image files are provided; Docker availability and runtime results are recorded in `docs/VALIDATION.md`.

## Checks and troubleshooting

```powershell
.\.venv\Scripts\python.exe -m pytest -q
Set-Location frontend
npm test
npm run build
```

Tests cover rule thresholds, provenance/time correlation, IPv4/IPv6 exclusions, authentication, rate limiting, confirmation, simulated/automatic enforcement, expiry, removal, adapter failures, graph comparison, CRUD, imports, review, notes and JSON/CSV/PDF APIs. See [validation results](docs/VALIDATION.md).

- **No tables / startup database errors:** run Alembic from the repository root with the intended `.env`; startup does not silently create schemas.
- **No admin / invalid credentials:** create the account once. To change credentials, set administrator variables and use `reset-password`. Existing `.env` does not change an already-hashed password.
- **Port occupied:** stop the earlier owned server or choose another port; update Vite proxy and allowed origins if needed. Keep one collector process.
- **pip/uv temporary-directory permissions:** set uv cache to `.cache/uv`; pytest uses `.cache/pytest`. Registry downloads require network permission. A broken ensurepip does not prevent uv installation into an existing venv.
- **CORS / session problems:** consistently use `127.0.0.1` or `localhost`, not both. These are different cookie hosts. Use the Vite proxy. `COOKIE_SECURE=true` requires HTTPS. Check origin configuration and eight-hour session expiry.
- **No live label:** the safe default is correct. Check the configured source, permissions, clock, fresh timestamps and running monitor. A readable historical file is not a live sensor.
- **Model unavailable:** migrate, run training, check `MODEL_PATH` and restart if needed. Do not upload model artifacts. Only matching trusted package versions should load joblib.
- **Block refused:** inspect policy, threshold, exclusions, recent live evidence if real, rate limit, and audit. Simulated blocks require manual/automatic policy too. Detection-only cannot create blocks.
- **Pending/error real block:** treat as uncertain and follow the lab reconciliation procedure; never delete history to hide a failed side effect.
- **Graph changes not reflected:** rerun analysis after editing. Results are invalidated on scenario edits. Scenario-only defense restrictions do not mutate baseline rules.
- **Long imports / reports:** local bounded synchronous processing can take time; report exports include up to 10,000 events. Use small batches or a dedicated ingestion/export queue for larger deployments.

## Honest limits

This is a single-node research application, not a production SOC or complete NDR product. It lacks MFA/SSO, distributed rate limiting, tenant separation, tamper-evident audit storage, automated retention, calibrated real-world ML, full packet capture, detection of every technique, sensor deployment orchestration, live Zeek collection and external reputation/geolocation services. General event APIs are administrator-created simulations; uploads are replay. Virtual graph assets are not auto-discovered. Live nftables behavior is implemented but requires isolated Linux-lab verification before use; no real firewall was changed during development. Captured source IPs may be shared/spoofed. Use an authenticated TLS reverse proxy, restricted network exposure, separate least-privilege enforcement service, secrets management, current dependency security review and real labeled evaluation before considering production deployment.
