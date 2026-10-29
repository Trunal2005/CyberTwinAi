# CyberTwin AI — project analysis

Historical pre-CN assessment. For the current ten-page application, PCAP workflow and presentation assets, start with the [root README](../README.md), [CN practical](../docs/CN_PRACTICAL.md) and [publication checks](../docs/PUBLICATION_VALIDATION.md).

Reviewed against the implementation and saved validation artifacts on 25 October 2026.

CyberTwin AI is a functional local research application combining rule-based intrusion detection, source-IP investigation, controlled enforcement workflows, synthetic-data machine learning, and a graph-based network digital twin. It is suitable for a college demonstration when the distinction between simulation and actual network security is explained.

## Local access

- Application: **http://127.0.0.1:8000/**
- Equivalent loopback hostname: **http://localhost:8000/**
- Interactive API documentation: **http://127.0.0.1:8000/docs**
- Hindi walkthrough viewer: **http://127.0.0.1:8000/walkthrough/**
- Health check: **http://127.0.0.1:8000/api/health**

The backend serves both the built frontend and API. Use one hostname consistently because browser cookies for `localhost` and `127.0.0.1` are separate. These URLs work on this computer only; the service is bound to loopback and is not publicly hosted. If stopped, run `scripts/start.ps1` from the repository root and keep the process running. No credentials are included in this report or the video.

## Implementation assessment

| Area | Implemented behavior | Practical limit |
|---|---|---|
| Frontend | Nine API-connected React pages, charts, event review, topology controls and exports | Browser workflows are designed for a local administrator |
| Backend/data | FastAPI, Pydantic, SQLAlchemy, Alembic and indexed SQLite records | Single-process collector, rate limits and action mutex |
| IDS | Authentication, port-diversity, connection-rate, transfer-burst and engine-signature rules | A bounded indicator set, with false positives and incomplete coverage |
| Provenance | Simulation, imported replay and configured live collection remain distinct | Live sensor/interface correctness still requires administrator verification |
| IP investigation | Timestamps, event history, services, virtual asset matches, notes and blocks | IP address is not proof of a person's identity |
| IPS | Detection-only/manual/automatic modes, previews, confirmations, exclusions, expiry, audit and failure records | Simulation does not drop packets; real nftables needs separate authorized Linux-lab validation |
| ML | Synthetic generator, reproducible split, majority baseline, Random Forest, persistence, metrics and prediction API | No real-world efficacy or calibrated-confidence claim is supported |
| Twin | Directed NetworkX reachability, critical-asset paths, scenario restrictions, patching/isolation and comparisons | Simplified assumptions; possible paths are not observed attacker movements |
| Reports | JSON/CSV/PDF exports and documented APIs | Report and history limits are explicit; not an enterprise reporting queue |
| Authentication | Salted PBKDF2 hashes, opaque expiring sessions, HttpOnly cookies, role checks and CSRF defenses | No MFA, SSO, tenant separation or tamper-evident audit service |

## Verified model results

The persisted synthetic benchmark uses seed 42 with 1,800 training rows and 600 held-out test rows. Suspicious-class precision is 0.7695, recall 0.7457, F1 0.7574 and false-positive rate 0.2104. The confusion matrix is `[[244, 65], [74, 217]]`. These are synthetic-development results; they must not be presented as actual production-network detection accuracy.

## Digital twin interpretation

Risk is calculated as:

`100 × Σ(reachable asset criticality × vulnerability) / Σ(all asset criticality × 10)`

Critical assets have criticality at least four. Patching sets the modeled vulnerability to zero and stops onward traversal from a patched pivot except the initial compromised node. A demonstrated web-server scenario changed modeled risk from 22.3 to 0 after restricting direct web→database access and patching the application server. This is a calculation under declared graph assumptions, not proof of a secure real network. Path enumeration is capped at 500 paths and eight hops; modification counts are not measured downtime or financial savings.

## Validation evidence and priorities

The saved validation record reports 33 backend and seven frontend tests passing, a successful production build, browser navigation checks and real-server report exports. Those checks were performed during implementation; creating this video does not constitute a new full test run. In this turn the localhost health endpoint was checked again and returned HTTP 200.

Before considering a production deployment:

1. Evaluate the ML model on an authorized, documented real dataset with host/session/time isolation, calibration, repeated runs and human-reviewed false positives.
2. Validate Suricata capture and actual packet handling in an isolated Linux lab. Separate privileged enforcement from the public application process.
3. Add TLS, MFA/SSO, centralized secrets, shared rate limits, least-privilege roles, retention and tamper-evident audit storage.
4. Add ingestion/export workers, collector recovery checkpoints, bounded graph execution and workload testing.
5. Validate PostgreSQL and Docker runtime independently. Zeek ingestion is currently unimplemented.
6. Preserve per-rule score contributions and all matched rule identifiers as the detection engine grows; a single primary label may not describe every contributing signal.

The Hindi/Hinglish video in `deliverables/video/` is an audience-facing presentation with AI-generated narration, illustrative diagrams, an existing simulation-workspace screenshot, captions and a transcript. It contains no administrator password and does not claim that its visuals are a recording of real attacks or live firewall enforcement.

The final MP4 is 14 minutes 12 seconds, 1920×1080, H.264 video with AAC narration and 20 embedded chapters. All audio/video streams decoded successfully. Burned Hindi captions, SRT/VTT files, a transcript and a chapter-based local viewer are included.
