> Archived pre-CN recording. The current video and viewer are documented in [README.md](README.md).

# CyberTwin AI — actual website walkthrough

**Corrected format:** short project introduction followed by the actual running website, menu navigation, scrolling, filtering, event details, review, IP investigation, policy preview, simulated block creation/removal, virtual network, what-if comparison, model prediction and PDF export.

**Duration:** 8 minutes 5 seconds. **Format:** 1920×1080 H.264 video, AAC Hindi narration, 13 embedded chapters, and Hindi captions.

Watch: http://127.0.0.1:8000/walkthrough/ or http://127.0.0.1:8000/walkthrough/site.html

The visuals are genuine background browser video recordings of the unchanged application, captured using the same method as the Anumitra website explanation. They are edited and time-scaled to match the narration. No presentation slides, OBS capture, desktop recording or visible Chrome windows are used.

A disposable simulation database under `.cache/site-walkthrough/` holds all recording actions. The main application database is unchanged. Authentication occurs off camera using recording-only credentials held in memory. Simulated actions never affect packets or the host firewall.

The original slide-based video is retained as an archive, but the main viewer now plays the actual-site video. `actual-site-validation.json` records source counts, page errors, full decoding and the final file hash. The narration is AI-generated; caption timing is approximate within each recorded scene.

Files: `CyberTwin-AI-Actual-Site-Hindi.mp4`, `Actual-Site-Hindi-Transcript.md`, `Actual-Site-Hindi-Subtitles.srt`, `actual-site-subtitles.vtt`, `site-chapter-timing.json`.

Reproduce: run `scripts/prepare_site_demo.py`, `scripts/narrate_site_demo.py`, `scripts/record_site_demo.mjs`, `scripts/encode_site_demo.py`, then `scripts/publish_site_walkthrough.py`. Install the optional tools and follow the portable reproduction commands in `docs/REVIEWING.md`. Media dependencies remain isolated in `.cache/video-deps/`.
