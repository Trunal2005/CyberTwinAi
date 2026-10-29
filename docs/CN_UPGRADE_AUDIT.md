# Computer Networks upgrade audit

Starting commit: `cca6edc63425855cd243905908620cd734c023ab` (main). Starting working tree clean. Existing data, environment, migrations and repository history must be preserved. No automatic push is authorized for this upgrade.

Inspected backend, frontend, migrations, tests, samples, scripts, docs, workflow, README, dependency declarations, Docker and environment configuration before implementation.

| Category | Starting evidence and affected files | Reproduction or consequence |
|---|---|---|
| Fully implemented and verified previously | `security.py`, `main.py`, existing 33 backend and 7 frontend regressions; `docs/VALIDATION.md` | Authenticated sessions, confirmation, safe simulation, CRUD, reports and twin comparisons have existing tests; baseline rerun recorded in final validation |
| Partially implemented | `detection.py:from_eve`, `schemas.py:Features`, `main.py:worker` | EVE keeps only selected fields; missing features default to zero; flow IDs, raw evidence, directional bytes and persistent collector offsets absent |
| Incorrect correlation | `detection.py:classify/ingest` | Eight ports to eight different destinations from one source trigger SCAN-001; retrying a record creates another event; same-flow engine records may inflate connection rate |
| Incorrect or unsafe verification | `firewall.py:NftablesAdapter.unblock` | JSON substring search cannot compare canonical compressed/expanded IPv6 addresses and is not restricted to set elements |
| Missing | No packet parser, traffic analysis router or persistent flow model | PCAP upload unsupported; no normalized flow-to-alert-to-action-to-map identifiers, traffic overlay or playback |
| Partially implemented ML | `ml.py:predict` | Absent features silently become zero; cache keyed only by mtime; no local real-dataset grouped evaluation CLI |
| Implemented but insufficiently bounded | `twin.py:analyze` | Paths capped at 500 and 8 hops, but hop cutoff is not reflected in the truncated flag; large path searches lack an exploration budget |
| Partially implemented visualization | `frontend/src/main.tsx:Twin` | Saved device coordinates exist but drag disabled; graph shows hypothetical access only; no observed-flow journey |
| Environment dependent and unavailable | `firewall.py`, `docs/LAB.md`, Docker/PostgreSQL integrations | Windows has no Linux nft kernel or authorized inline sensor lab; real packet dropping remains NOT VERIFIED |

The implementation follows this evidence: retain existing Event/API compatibility, add a nullable normalized flow layer and frozen new migration, bounded offline parsing and explicit observation provenance. Existing v1/v2 migrations will not be edited. Real integrations remain opt-in.

## Baseline execution

The documented baseline commands were executed: `.\.venv\Scripts\python.exe -m pytest -q` returned **33 passed**, and `npm test` in frontend returned **7 passed**; `npm run build` completed. One existing upstream TestClient deprecation warning remains. Normal tests were run outside the restricted Windows sandbox because its subprocess/threading/file restrictions do not represent a regular developer environment.

Regression evidence: the new mocked expanded-IPv6 unblock test initially failed with `len(deleted) == 0` where one delete was required. After structured, canonical set-element parsing it passes. Target correlation, duplicate replay and missing-feature preservation are covered by new tests. A later final review found and fixed default fields leaking through the PCAP intermediate JSON; tests now require the keys to be absent, rather than merely zero. A Windows collector fixture used text newline translation and expected LF-only offsets; it was corrected to write exact bytes. The collector's byte offset itself was correct.
