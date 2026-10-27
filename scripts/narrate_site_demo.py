from concurrent.futures import ThreadPoolExecutor,as_completed
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.cache/video-deps'))
from gtts import gTTS
WORK=ROOT/'.cache/site-walkthrough'
script=json.loads((ROOT/'deliverables/video/site-narration.json').read_text(encoding='utf-8'))
def narrate(scene):
    path=WORK/f"scene-{scene['index']:02d}.mp3"
    if path.exists() and path.stat().st_size>1000:return scene['index']
    for attempt in range(3):
        try:gTTS(scene['text'],lang='hi',timeout=40).save(str(path));return scene['index']
        except Exception:
            if attempt==2:raise
            time.sleep(attempt+2)
with ThreadPoolExecutor(max_workers=2) as ex:
    for task in as_completed([ex.submit(narrate,s) for s in script]):print(f'Hindi site narration {task.result()}/{len(script)} ready',flush=True)
