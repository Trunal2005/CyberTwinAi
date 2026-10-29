# CN upgrade validation 28 October 2026

Starting HEAD `cca6edc63425855cd243905908620cd734c023ab`; no new commit/push. Windows, Python 3.13 virtual environment, Node 20.19.4. Database migration is revision 0003. Tests use disposable databases and simulated or mocked enforcement. No host networking/firewall configuration was changed.

| Exact command or check | Result |
|---|---|
| Baseline `.\.venv\Scripts\python.exe -m pytest -q` | 33 passed |
| Baseline `npm test` from frontend | 7 passed |
| Final `.\.venv\Scripts\python.exe -m pytest -q` | **71 passed**, 1 upstream deprecation warning, 66.63 seconds |
| Final `npm test` from frontend | **11 passed**, three files |
| `npm run build` from frontend | Pass; TypeScript and Vite, no bundle-size warnings |
| `node tests/browser_cn.mjs` | **10 checkpoints pass**, zero page errors; isolated port 8004/database |
| `uvx --cache-dir .cache/uv --from ruff==0.14.3 ruff check --select F821,F811,F822,F823 backend tests/test_cn.py scripts/backup_database.py scripts/generate_cn_capture.py` | Pass |
| `uv --cache-dir .cache/uv pip check --python .venv/Scripts/python.exe` | 48 packages compatible |
| PowerShell AST parse of `scripts/setup.ps1` | Pass; helper refuses migration while port 8000 is listening |
| `.\.venv\Scripts\python.exe scripts/generate_cn_capture.py` | Both owned capture formats generated; no traffic sent |
| SQLite revision 0002 with an existing event → revision 0003 | Pass; original evidence and row preserved, no invented normalized flow |
| Existing user database backup and migration | Pass; users 1 / events 127 / blocks 0 preserved; virtual devices 9→11 |
| Existing synthetic benchmark retraining after backup | Same confusion matrix `[[244,65],[74,217]]` |
| `.\.venv\Scripts\python.exe scripts/smoke.py` against localhost 8000 | Pass: health/status/overview/events/network/scenarios/model/reports and JSON/CSV/PDF/OpenAPI |
| Real live sensor and Linux nftables packet dropping | **NOT VERIFIED**; no isolated Linux kernel/sensor environment supplied |
| Published real dataset evaluation | **NOT VERIFIED**; no user dataset supplied/downloaded. CLI tested with generated grouped fixtures only |
| PostgreSQL, Docker runtime and new remote CI | **NOT VERIFIED** in this upgrade; local SQLite tests do not establish these integrations |

## Browser demonstration checkpoints

1. Browser login using a disposable administrator.
2. PCAP replay, original evidence and detection-only decision.
3. Protocol filtering and duplicate replay producing zero new observations.
4. Explicit simulated alert approval and persisted no-real-packets timeline.
5. Observed map, play/pause/speed/scrub/reduced motion and linked flow.
6. Pointer dragging persists virtual device position through the API.
7. Browser defense comparison persists lower modified modeled risk.
8. Flow-to-source investigation navigation.
9. Loaded model metadata and actual prediction.
10. Same-observation JSON analytics and PDF report.

Saved result: `docs/validation/cn-browser.json`. Reviewed screenshots: `docs/screenshots/cn-traffic-analysis.png`, `cn-flow-journey.png`, `cn-observed-network.png`, `cn-mobile.png`. Screenshots contain owned test data and a disposable username, no passwords. Browser DBs, logs and models remain ignored under `.cache/`.

## Failed checks and fixes

- The deliberately red nftables expanded/compressed IPv6 unblock regression failed before the fix: deletion was not executed. It passes with canonical named-set JSON parsing.
- An intermediate JSX syntax error and missing jsdom directive in new frontend tests were corrected; final 11 tests/build pass.
- Initial browser assertions used the wrong login text and matched collapsed background details. Assertions were corrected to the actual visible controls/dialog, with no weakening of application checks.
- An intermediate full run had 61 passes and one Windows fixture failure: `write_text` changed LF to CRLF while the assertion expected LF byte counts. The fixture now writes exact bytes; final 71 tests pass.
- Final review added regressions for missing PCAP feature keys, unknown-duration burst input, explicit real-action thresholds, packet count bounds and excluding Ethernet padding from IP counters. These are included in the final 71 count.

One upstream Starlette TestClient warning recommends httpx2. The existing pinned httpx client continues to pass all tests; warning handling was not suppressed. No Linux or real-data result is fabricated to fill an unavailable check.
