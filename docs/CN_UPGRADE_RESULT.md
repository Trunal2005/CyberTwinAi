# CyberTwin AI CN engineering upgrade result

Historical implementation record from 28 October 2026. For the complete repository publication and newer checks, see [PUBLICATION_VALIDATION.md](PUBLICATION_VALIDATION.md).

## Executive summary

The existing FastAPI/React security platform now has a persistent Computer Networks observation layer. Small owned packet captures and supported logs produce normalized flows, explainable IDS evidence, correlated IPS decisions, traffic analytics and observed endpoint overlays on the existing virtual model. Authentication, confirmation, provenance and simulation defaults remain intact. No host firewall configuration was changed and no Git push was made.

Starting commit: `cca6edc63425855cd243905908620cd734c023ab`. Existing local account and all 127 events were preserved by backed-up migration 0003. Two additive virtual roles bring the topology to 11 assets. Historical events are not retroactively converted into measured flows. The synthetic benchmark was backed up and reproduced unchanged.

## Before and after

| Area | Before | After and evidence |
|---|---|---|
| Offline capture | No packet-capture input | Authenticated PCAP/PCAPNG subprocess parsing; owned sample has 13 packets, 11 conversations and one scan alert |
| Flow evidence | Event features, missing defaults ambiguous | Nullable protocol/tuple/counters/state, original bounded log/header evidence, capture SHA256 and stable IDs |
| Replay reliability | No dedup or durable collector offset | Record fingerprints, cumulative counters, persistent checkpoints, partial-line/restart regressions |
| Scan correlation | All targets' ports could combine | Same source, target and transport, sensor/origin isolation; duplicate flow identities counted once |
| Other IDS evidence | Core auth/rate/burst/signature rules | Preserved core rules, missing-duration guard, rejected-connection, statistical and explicit access-policy indicators |
| IPS verification | IPv6 unblock substring check | Canonical named-set parsing, read-only reconciliation and explicit scope of verification |
| Integrated journey | Separate event, graph and block views | Flow/event/decision/block IDs connect original evidence, threshold, approval and adapter outcome |
| Visualization | Virtual access paths only | Observed endpoint overlay, unmatched endpoints, provenance, playback/pause/speed/scrub, reduced motion and saved positions |
| Twin analysis | Boolean reachability; path/hop caps incompletely signaled | Transport/service rules, route query, before/after service summaries and a 20,000-step budget with lower-bound truncation |
| ML | Synthetic RF; missing inputs could become defaults | Same synthetic result, versioned features, disclosed train-only mean imputation, missing-model fallback and separate grouped CSV research CLI |
| Analytics | Event-oriented charts | Stored flow protocol, endpoint/service/conversation counters, coverage-aware bytes/packets, durations, span-average rate and reproducible exports |

## IDS evidence

The offline sample includes a normal three-packet TCP conversation, DNS over UDP, ICMPv6 and eight source-port-distinct SYN observations to eight ports of one owned modeled web endpoint. Ten conversations remain below the suspicious threshold; the eighth scan conversation crosses SCAN-001. Its seven preceding event/flow IDs and original header evidence are inspectable. No scanning was performed on a network.

Regressions exercise authentication only with explicit source evidence, exact burst boundaries and unknown duration, 100 distinct connection observations, target/protocol/sensor/origin separation, out-of-order inputs, cumulative EVE records, duplicate imports, malformed input, IPv6, rejected states, a 30-observation statistical baseline and destination/source-CIDR access policy. Normal traffic is not assigned a fabricated malicious label. IDS risk is separate from supporting model probability.

The primary-rule evidence links its actual contributing observations; full correlation context IDs support other matched evidence. Correlation is a bounded preceding event-time window. Late events do not retroactively rewrite earlier alerts. These constraints are documented rather than presented as globally order-independent stream processing.

## IPS evidence and verification scope

- **Simulated and exercised:** detection-only, confirmed manual approval, automatic-mode safeguards, protected address refusal, temporary expiry/removal, action budget, failure history and concurrent idempotent requests.
- **Mocked and exercised:** nftables readiness, canonical IPv6 named-set removal and provenance/threshold gates. The IPv6 regression failed before the fix and passed after it.
- **Implemented configuration and procedure:** optional Linux timeout-set adapter, read-only reconciliation and namespace-only local HTTP/drop-counter experiment.
- **NOT VERIFIED:** actual Linux kernel packet dropping, installed Suricata live capture, genuine inline Suricata IPS or application-to-kernel end-to-end enforcement. Windows provides none of these lab conditions. Set membership is never promoted to proof that a packet dropped.

All UI simulation approvals explicitly state **SIMULATED — NO REAL PACKETS WERE BLOCKED**. Decisions, block IDs, expiry and outcomes persist. Startup creates no firewall rules. Real actions require explicit Linux opt-in, exclusions, ready adapter and recent qualifying collector-owned evidence. No production-security efficacy is claimed.

## Network visualization evidence

The browser test exercises real UI replay and flow inspection, protocol filtering, an explicitly approved simulated action, observed-map playback and scrubbing, reduced motion, pointer-drag position persistence, before/after defense comparison and source-IP investigation navigation. Straight observed endpoint edges do not assert physical forwarding paths. Gray modeled access and purple scenario paths remain topology models. Unmatched addresses remain visibly unmatched. Screenshots are in `docs/screenshots/cn-*.png`; machine-readable browser results are in `docs/validation/cn-browser.json`.

## AI and Data Science evidence

The original synthetic generator remains seed 42, 2,400 rows, stratified 1,800 train / 600 held-out rows, Random Forest 120 trees and a majority-class baseline. Reproduced confusion matrix is `[[244,65],[74,217]]`: suspicious precision about 0.770, recall 0.746, F1 0.757, false-positive rate 0.210 and false-negative rate 0.254. Metrics are computed by training, not UI constants. Missing inference values use disclosed training-only feature means where the artifact supports them. They are never stored as measured authentication or traffic values.

The separate local research CLI supports normalized core features or documented CICFlowMeter columns, strict cleaning and duplicate checks, and user-documented capture/host/day groups. It compares majority, scaled logistic regression and Random Forest on one group-disjoint held-out split and records sample sizes, groups, class balance, metrics, input hash and measured timings. Regression verification used generated fixtures only. **No published real dataset was downloaded or evaluated; no CICIDS2017 score is claimed.** Sensor byte semantics require explicit runtime alignment.

Traffic summaries use the same persisted Flow IDs. Null coverage is shown. Minute buckets attribute aggregate counters to first-seen time and span-average throughput is clearly described. No RTT, loss, retransmission, congestion or link utilization is inferred from insufficient data.

## Test and setup report

Final exact commands/results are recorded in CN_UPGRADE_VALIDATION.md. Baseline was 33 backend and 7 frontend tests. Final verification passed 71 backend tests, 11 frontend tests, the production build and ten browser checkpoints with zero page errors. Dependency consistency checked 48 packages. Existing-server smoke checks passed eight read APIs, JSON/CSV/PDF exports and OpenAPI generation using the preserved administrator account. The upstream Starlette TestClient deprecation remains non-failing.

Windows clean setup:

```powershell
Set-Location "C:\projects\CN project"
# Current upgraded workspace. Stop the server before rerunning setup.
# A clean checkout uses the same steps after this upgrade is published or copied.
.\scripts\setup.ps1
# On a fresh setup, edit the created .env with your own credentials, then rerun:
.\scripts\setup.ps1
.\scripts\start.ps1
```

Python 3.13 and Node 20.19+ or 22 are documented. No paid API, cloud account, Npcap driver, admin privileges or Linux installation is required for normal replay. Existing setups must stop the server before migration. The setup helper preserves accounts, backs up SQLite/model artifacts and preserves a configured research model. The app is running locally at http://127.0.0.1:8000/ after this upgrade; use existing credentials.

## Shortest professor demonstration

Open **PCAP and Traffic Analysis**, upload `samples/cn-demo.pcap`, show 13 packets / 11 conversations and protocol/service details. Inspect source 192.0.2.44 port 27 for SCAN-001 and actual related observations. Explicitly configure manual threshold 70 in simulation, preview/confirm a temporary action and show the no-real-packets timeline. Open **Network Digital Twin → Observed traffic**, replay/pause/scrub and inspect endpoints; distinguish MODELED PATH from observed traffic. Under Scenario, restrict web→db and patch app; compare modeled risk. Show actual ML metadata and one prediction, then export the same flow/report evidence. Full page-by-page script: CN_PRACTICAL.md.

## Remaining limitations and Git state

Real capture/enforcement, real-dataset external performance, PostgreSQL integration and Docker runtime remain **NOT VERIFIED** in this environment. Continuous live Zeek, full packet/stream reassembly, physical route discovery, distributed workers/rate limiting, calibrated real-world ML and production SOC hardening are not implemented. PCAP is deliberately bounded. Large imports still have synchronous/per-record work; timestamps/counters and mixed-sensor duplication have documented limits. Manual retention is opt-in and dry-run by default. No workload was sent to external targets.

No remote history was changed. HEAD remains the starting commit and all upgrade changes are visible as local modified/untracked files. No new commit or push was performed. The earlier remote main remains available for the prior version; the upgrade must be explicitly published before a friend cloning GitHub receives it.

## Exact file changes

| File | Purpose |
|---|---|
| `.dockerignore` | Exclude local caches and unrelated deliverables from Docker build context. |
| `.gitattributes` | Preserve binary PCAP and PCAPNG fixtures across clones. |
| `.github/workflows/checks.yml` | Add isolated headless browser verification and screenshot artifacts to CI. |
| `README.md` | CN upgrade, safe Windows setup and links to technical evidence. |
| `backend/db.py` | Nullable Flow model, explicit prevention correlation and indexed source/time history. |
| `backend/detection.py` | Target/sensor-aware deduplicated IDS, evidence links, missing-data guards and policy decisions. |
| `backend/firewall.py` | Structured canonical nftables membership, qualifying live evidence and read-only reconciliation. |
| `backend/main.py` | Integrate routers, checkpoint recovery, correlated approval, truthful status and flow-aware reports. |
| `backend/ml.py` | Versioned metadata, measured timing, declared imputation, cache identity and unavailable-artifact fallback. |
| `backend/schemas.py` | Normalized observation metadata, endpoint coherence, segments, service permissions and optional model inputs. |
| `backend/seed.py` | Explicit additive switch/external lab topology and preserve checked-in samples by default. |
| `backend/twin.py` | Service-aware reachability, bounded enumeration, accurate truncation and service summaries. |
| `docs/LAB.md` | Namespace-only local packet-counter procedure; real execution remains NOT VERIFIED. |
| `docs/openapi.json` | Updated offline API schema snapshot. |
| `frontend/src/main.tsx` | Integrate traffic page, linked evidence, service summaries, model metadata and source investigation. |
| `frontend/src/style.css` | Responsive traffic analytics, evidence timeline and reduced-motion styles. |
| `requirements.lock.txt` | Constrain Scapy alongside existing validated environment. |
| `requirements.txt` | Pin maintained Scapy parser dependency. |
| `scripts/lab.nft` | Dedicated optional lab rules with observable drop counters. |
| `backend/maintenance.py` | Opt-in bounded dry-run retention for old low-risk non-live data. |
| `backend/observations.py` | Canonical flow/record identities, cumulative counter updates and Zeek JSON normalization. |
| `backend/pcap.py` | Bounded offline Scapy PCAP/PCAPNG parser and captured IP-header aggregation. |
| `backend/pcap_worker.py` | Disposable parser subprocess with JSON-only result channel. |
| `backend/research_ml.py` | User-supplied grouped real-data CSV research CLI and reproducible model comparisons. |
| `backend/traffic_api.py` | Authenticated replay, flow analytics/filtering/export, map overlays, route and policy endpoints. |
| `docs/CN_PRACTICAL.md` | CN concepts, implementation semantics, operating limits and page-by-page professor demo. |
| `docs/CN_UPGRADE_AUDIT.md` | Starting commit, categorized pre-implementation audit and regression evidence. |
| `docs/RESEARCH_DATA.md` | Dataset provenance, feature mapping, grouped evaluation and unverified real-data limits. |
| `docs/screenshots/cn-flow-journey.png` | Reviewed actual application screenshot. |
| `docs/screenshots/cn-mobile.png` | Reviewed actual application screenshot. |
| `docs/screenshots/cn-observed-network.png` | Reviewed actual application screenshot. |
| `docs/screenshots/cn-traffic-analysis.png` | Reviewed actual application screenshot. |
| `docs/validation/cn-browser.json` | Saved ten-checkpoint browser evidence with zero page errors. |
| `frontend/src/network.test.tsx` | Upload/filter/missing-data/IPS evidence and playback component regressions. |
| `frontend/src/network.tsx` | Traffic page, flow journey, approval, observed-map playback, saved positions and modeled policy controls. |
| `migrations/versions/0003_network_flows.py` | Additive frozen migration preserving legacy accounts/events and applied revisions. |
| `samples/cn-demo.pcap` | Owned deterministic TCP, DNS/UDP, ICMPv6 and synthetic scan capture. |
| `samples/cn-demo.pcapng` | Equivalent owned PCAPNG fixture. |
| `scripts/backup_database.py` | Consistent SQLite and model backups before upgrade. |
| `scripts/generate_cn_capture.py` | Generate deterministic test headers locally without sending packets. |
| `scripts/setup.ps1` | Windows setup/upgrade with preserved accounts, backups, migrations and build. |
| `tests/browser_cn.mjs` | Disposable-database browser checks for the integrated professor demonstration. |
| `tests/test_cn.py` | Normalization, PCAP, IDS, IPS, migration, ML, retention and graph regressions. |
| `docs/CN_UPGRADE_RESULT.md` | Final technical result, acceptance evidence and change manifest. |
| `docs/CN_UPGRADE_VALIDATION.md` | Final check commands, results and environment boundaries. |
| `docs/REVIEWING.md` | Link the current CN review, evidence and local publication status. |
| `docs/VALIDATION.md` | Preserve historical checks and point to the latest upgrade results. |
