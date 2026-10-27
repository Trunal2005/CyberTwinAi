"""Point the existing local viewer at the corrected, actual-website video."""
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'deliverables/video'
timing=json.loads((OUT/'site-chapter-timing.json').read_text())
source=(OUT/'index.html').read_text(encoding='utf-8')
archive=OUT/'slides-viewer.html'
if not archive.exists():archive.write_text(source,encoding='utf-8')
html=source.replace('CyberTwin-AI-Hindi-Walkthrough.mp4','CyberTwin-AI-Actual-Site-Hindi.mp4').replace('CYBERTWIN AI / RESEARCH PRESENTATION','CYBERTWIN AI / ACTUAL WEBSITE DEMO')
html=html.replace('Hindi-Transcript.md','Actual-Site-Hindi-Transcript.md').replace('CyberTwin-AI-Hindi-Subtitles.srt','Actual-Site-Hindi-Subtitles.srt')
html=html.replace('poster.jpg','actual-site-poster.jpg').replace('subtitles.vtt','actual-site-subtitles.vtt')
html=html.replace('Understand the project, in Hindi.','CyberTwin AI: actual website walkthrough')
html=html.replace('Detailed architecture, detection, prevention, machine learning and digital twin walkthrough.',
                  'Short project introduction, followed by actual website navigation, clicks, scrolling and demos in Hindi.')
html=html.replace('20 chapter walkthrough',f"{len(timing['chapters'])} actual website chapters")
html=html.replace('AI-generated narration with project screenshots and illustrative diagrams. Simulation and synthetic model results are explicitly labeled; this is not footage of real attacks or a claim of production security.',
                  'All visuals are actual recordings of the running website, using an isolated simulation database. No presentation slides. Hindi narration and captions are added over the recordings; passwords stay off screen.')
html=re.sub(r'const chapters=.*?;const player=',lambda m:'const chapters='+json.dumps(timing['chapters'])+';const player=',html,flags=re.S)
html=re.sub(r'stamp\(\d+(?:\.\d+)?\)\+',f"stamp({timing['duration_seconds']})+",html)
html=html.replace('<title>CyberTwin AI · Hindi walkthrough</title>','<title>CyberTwin AI · Actual website demo in Hindi</title>')
(OUT/'index.html').write_text(html,encoding='utf-8')
(OUT/'site.html').write_text(html,encoding='utf-8')
captions=(OUT/'Actual-Site-Hindi-Subtitles.srt').read_text(encoding='utf-8')
(OUT/'actual-site-subtitles.vtt').write_text('WEBVTT\n\n'+re.sub(r'(\d\d:\d\d:\d\d),(\d{3})',r'\1.\2',captions),encoding='utf-8')
duration=timing['duration_seconds'];minutes=int(duration//60);seconds=round(duration%60)
(OUT/'ACTUAL_SITE_README.md').write_text(f'''# CyberTwin AI — actual website walkthrough

**Corrected format:** short project introduction followed by the actual running website, menu navigation, scrolling, filtering, event details, review, IP investigation, policy preview, simulated block creation/removal, virtual network, what-if comparison, model prediction and PDF export.

**Duration:** {minutes} minutes {seconds} seconds. **Format:** 1920×1080 H.264 video, AAC Hindi narration, 13 embedded chapters, and Hindi captions.

Watch: http://127.0.0.1:8000/walkthrough/ or http://127.0.0.1:8000/walkthrough/site.html

The visuals are genuine background browser video recordings of the unchanged application, captured using the same method as the Anumitra website explanation. They are edited and time-scaled to match the narration. No presentation slides, OBS capture, desktop recording or visible Chrome windows are used.

A disposable simulation database under `.cache/site-walkthrough/` holds all recording actions. The main application database is unchanged. Authentication occurs off camera using recording-only credentials held in memory. Simulated actions never affect packets or the host firewall.

The original slide-based video is retained as an archive, but the main viewer now plays the actual-site video. `actual-site-validation.json` records source counts, page errors, full decoding and the final file hash. The narration is AI-generated; caption timing is approximate within each recorded scene.

Files: `CyberTwin-AI-Actual-Site-Hindi.mp4`, `Actual-Site-Hindi-Transcript.md`, `Actual-Site-Hindi-Subtitles.srt`, `actual-site-subtitles.vtt`, `site-chapter-timing.json`.

Reproduce: run `scripts/prepare_site_demo.py`, `scripts/narrate_site_demo.py`, `scripts/record_site_demo.mjs`, `scripts/encode_site_demo.py`, then `scripts/publish_site_walkthrough.py`. Install the optional tools and follow the portable reproduction commands in `docs/REVIEWING.md`. Media dependencies remain isolated in `.cache/video-deps/`.
''',encoding='utf-8')
print(f'Local viewer updated: {minutes}:{seconds:02d}, {len(timing["chapters"])} actual website chapters')
