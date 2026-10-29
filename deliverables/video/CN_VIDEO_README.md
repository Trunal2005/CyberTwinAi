# Updated CyberTwin AI CN website explanation

Video: `CyberTwin-AI-CN-Site-Explanation-Hinglish.mp4`. Duration: 12.8 minutes. 1080p H.264/AAC with locally generated Hindi/Hinglish narration, 16 chapters and optional captions. No narration text or audio was sent to an external service.

Actual running application footage with clicks, scrolling, PCAP upload, SCAN-001 evidence, review, linked flow journey, IP notes, manual policy, simulated prevention, block removal, observed replay, before/after twin comparison, model prediction, monitoring and PDF export. Authentication stays off camera.

All recording actions use a disposable database under `.cache/cn-site-video-20261029/`; the primary database and firewall are unchanged. Replay and simulation are explicitly explained. Synthetic model metrics and modeled defense outcomes are not real-world performance claims. Captions use approximate within-beat timing.

Watch at http://127.0.0.1:8000/walkthrough/cn-demo.html while the application server is running. The default walkthrough also opens this updated version.

Reproduce: `python scripts/build_cn_video.py prepare`, `python scripts/build_cn_video.py narrate`, `node scripts/record_cn_video.mjs`, `python scripts/build_cn_video.py encode`, `python scripts/build_cn_video.py webm`, `python scripts/build_cn_video.py publish`. Optional media dependencies live in `.cache/video-deps` and Playwright in `tools/video`.

Offline speech: Piper 1.8.0 (https://github.com/OHF-Voice/piper1-gpl), GPL-3.0-or-later engine, installed separately under `.cache/local-tts`. Hindi voice: Pratham medium, trained by PravalX using AI4Bharat indicnlp_corpus. Voice card: https://huggingface.co/rhasspy/piper-voices/blob/main/hi/hi_IN/pratham/medium/MODEL_CARD . The voice card identifies the dataset license as CC-BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/). This is a noncommercial educational project demonstration. Model files and licenses remain with the local voice cache and are not bundled into the application. Download the public model and configuration into `.cache/cn-site-video-20261029/voice/` before local narration.

The local viewer automatically offers a VP9/Opus WebM fallback when a browser lacks H.264/AAC support. The Download MP4 button retains the original H.264/AAC file. Local browser playback, chapter selection and HTTP byte-range streaming passed; see `cn-player-validation.json`.
