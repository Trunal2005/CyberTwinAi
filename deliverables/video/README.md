# Hindi / Hinglish project walkthrough

**Updated actual-site video:** [CyberTwin-AI-Actual-Site-Hindi.mp4](CyberTwin-AI-Actual-Site-Hindi.mp4), 8 minutes 5 seconds, with genuine website navigation and Hindi explanation. Watch at **http://127.0.0.1:8000/walkthrough/**. See `ACTUAL_SITE_README.md` for the corrected recording. The slide-based video below is retained only as an archive.

The finished video is `CyberTwin-AI-Hindi-Walkthrough.mp4`.

Watch locally at **http://127.0.0.1:8000/walkthrough/** while the application server is running. Runtime: **14 minutes 12 seconds**, with **20 embedded chapters**. The MP4 is approximately **18.8 MB**. The complete video and audio streams passed a decoding check; details are in `media-validation.json`.

- 1080p presentation with Hindi AI-generated narration and English technical headings.
- Twenty chapters cover the problem, stack, modes, dashboard, IDS, investigation, IPS safeguards, ML, graph analysis, what-if comparison, scoring, security, reports, tests, limitations and demo procedure.
- Project screenshot and code-drawn diagrams; this is a narrated presentation, not talking-head footage or a recording of real attacks.
- Hindi captions are burned into the video. `CyberTwin-AI-Hindi-Subtitles.srt` is also supplied; caption timing is approximate within each chapter.
- `Hindi-Transcript.md` contains the full narration with chapter timestamps.
- `chapters.json` is the reviewed narration source; `chapter-timing.json` records generated timing.
- Narration contains no credentials or private logs. The sample screenshot is explicitly a simulation workspace.

To regenerate on Windows from the repository root, install the media-only dependencies into their isolated directory and run:

```powershell
uv --cache-dir .cache/uv pip install --target .cache/video-deps gTTS==2.5.4 imageio-ffmpeg==0.6.0
.\.venv\Scripts\python.exe scripts/create_walkthrough.py
.\.venv\Scripts\python.exe scripts/finalize_walkthrough.py
```

Generation requires network access for Hindi text-to-speech and Windows fonts/text rendering for correctly shaped captions. Narration segments and intermediate video files are cached under `.cache/walkthrough/`. The application's Python requirements and behavior are unchanged.
