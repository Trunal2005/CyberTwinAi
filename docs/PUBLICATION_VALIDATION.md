# Complete-project publication — 29 October 2026

This publication packages the Computer Networks upgrade, migration 0003, actual-site Hindi/Hinglish walkthrough, final A3 poster, screenshots, tests and clone/setup documentation. Existing local accounts, the primary database and the running server are not part of the commit.

## Validation

| Check | Result |
|---|---|
| Full backend suite | 72 passed; one upstream Starlette TestClient deprecation warning |
| Frontend suite | 11 passed in three files |
| TypeScript / Vite production build | Passed |
| Current browser workflow | 11 checkpoints passed; zero page errors, including direct Settings navigation |
| Clean local clone / setup | Pending final publication check |
| Media | 12:45, 16 chapters, MP4 full decode passed; WebM local playback, chapter seeking and byte-range streaming passed |
| Poster | One A3 portrait PDF; final visually reviewed version, fonts embedded |
| Secret/exclusion scan | 134 candidate files checked; no configured secret values, private-key/token patterns, private databases or oversized GitHub files found |

## Corrections included

- The prior GitHub backend run failed because `pytest.ini` requested `.cache/pytest` while the ignored `.cache` parent did not exist in a fresh checkout. The default test directory is now the ignored root-level `.pytest-tmp`, whose parent always exists.
- Traffic timelines accept ISO8601 timestamps with both whole-second and fractional-second precision when simulation and PCAP replay records are combined. A regression covers the mixed-source analytics request.
- Opening Settings directly no longer crashes while the initial public health response is being replaced by authenticated integration status. The browser workflow includes this regression.
- The latest video player includes a VP9/Opus WebM source for browsers without H.264/AAC support. Narration generation is offline; the optional archived online narrator is explicitly identified as historical.

GitHub Actions runs backend, frontend and browser jobs. The status on the repository is the authoritative remote CI result; local checks alone are not a claim that remote jobs passed.

## Reproduction and scope

Follow the root README from a fresh clone: install Python dependencies, create `.env` with your own credentials, migrate, create the administrator, seed with `--extend-network`, train, install/build the frontend and start Uvicorn. The README and reviewer guide link all final presentation assets.

These are isolated simulation/replay checks. They do not establish real Linux packet dropping, deployed sensors, PostgreSQL/Docker runtime or published real-dataset performance. Older dated validation documents remain historical evidence.
