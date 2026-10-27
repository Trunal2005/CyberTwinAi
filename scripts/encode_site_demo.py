"""Encode real website video captures with Hindi narration; no slide visuals."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'.cache/site-walkthrough'
OUT=ROOT/'deliverables/video'
sys.path.insert(0,str(ROOT/'.cache/video-deps'))
import imageio_ffmpeg
FF=imageio_ffmpeg.get_ffmpeg_exe()
script=json.loads((OUT/'site-narration.json').read_text(encoding='utf-8'))
recording=json.loads((WORK/'recording-scenes.json').read_text(encoding='utf-8'))
assert len(recording['scenes'])==len(script) and not recording['pageErrors']

def timestamp(seconds):
    ms=round(seconds*1000);sec,ms=divmod(ms,1000);minute,sec=divmod(sec,60);hour,minute=divmod(minute,60)
    return f'{hour:02d}:{minute:02d}:{sec:02d},{ms:03d}'

def duration(file):
    r=subprocess.run([FF,'-hide_banner','-i',str(file)],capture_output=True,text=True)
    m=re.search(r'Duration: (\d+):(\d+):(\d+\.\d+)',r.stderr)
    if not m:raise RuntimeError('Could not inspect recorded media')
    return int(m[1])*3600+int(m[2])*60+float(m[3])

def run(args,log):
    with (WORK/log).open('w',encoding='utf-8') as stream:
        subprocess.run([FF,'-hide_banner','-y',*map(str,args)],cwd=WORK,stdout=stream,stderr=stream,check=True)

parts=[];allsubs=[];offset=0;chapters=[];transcript=['# CyberTwin AI — actual website walkthrough (Hindi)','',
    'All visuals are video captures of the running application using an isolated simulation database. No presentation slides.','']
checks=[]
for rec,scene in zip(recording['scenes'],script):
    i=scene['index'];assert rec['index']==i
    stem=f'website-{i:02d}'
    audio=WORK/f'scene-{i:02d}.mp3';length=duration(audio)
    chunks=[]
    for sentence in re.split(r'(?<=[।.!?])\s+',scene['text']):
        words=sentence.split()
        while words:chunks.append(' '.join(words[:14]));words=words[14:]
    weight=sum(len(t) for t in chunks);elapsed=0;subs=[]
    for j,caption in enumerate(chunks):
        start=elapsed;elapsed+=length*len(caption)/weight
        subs += [str(j+1),f'{timestamp(start)} --> {timestamp(elapsed)}',caption,'']
        allsubs += [str(len(allsubs)//4+1),f'{timestamp(offset+start)} --> {timestamp(offset+elapsed)}',caption,'']
    (WORK/(stem+'.srt')).write_text('\n'.join(subs),encoding='utf-8')
    speed=length/rec['duration']
    # Full application viewport, actual clicks and scrolling. Time-scaled to narration.
    vf=(f"trim=start={rec['start']}:duration={rec['duration']},setpts=(PTS-STARTPTS)*{speed:.8f},fps=20,"
        f"scale=1536:960,pad=1920:1080:192:0:black,subtitles={stem}.srt:"
        "force_style='FontName=Nirmala UI,FontSize=9,Alignment=2,MarginV=6,Outline=1,Shadow=0',"
        "tpad=stop_mode=clone:stop_duration=0.3")
    run(['-i',WORK/f'site-scene-{i:02d}.webm','-i',audio,'-vf',vf,'-af','volume=3dB,apad=pad_dur=0.3',
         '-t',f'{length+.3:.3f}','-c:v','libx264','-threads','4','-preset','fast','-crf','22','-pix_fmt','yuv420p',
         '-c:a','aac','-b:a','128k','-ar','44100','-ac','2','-movflags','+faststart',WORK/(stem+'.mp4')],stem+'-encode.log')
    parts.append(f"file '{stem}.mp4'")
    chapters.append({'chapter':i,'title':scene['title'],'start_seconds':round(offset,3),'duration_seconds':round(length+.3,3)})
    transcript += [f"## {timestamp(offset).replace(',','.')}: {scene['title']}",'',scene['text'],'']
    checks.append({'scene':i,'actualWebsiteVideo':True,'rawSeconds':round(rec['duration'],3),'narrationSeconds':length})
    offset+=length+.3
    print(f'Encoded actual-site chapter {i}/{len(script)}: {scene["title"]}',flush=True)

(WORK/'site-concat.txt').write_text('\n'.join(parts),encoding='utf-8')
metadata=[';FFMETADATA1','title=CyberTwin AI - Actual Website Walkthrough in Hindi','artist=AI Hindi narration',
          'comment=Actual browser video with fictional simulation data; no slide visuals.']
for c in chapters:
    metadata += ['[CHAPTER]','TIMEBASE=1/1000',f"START={round(c['start_seconds']*1000)}",
                 f"END={round((c['start_seconds']+c['duration_seconds'])*1000)}",f"title={c['chapter']:02d}. {c['title']}"]
(WORK/'site-metadata.ffmeta').write_text('\n'.join(metadata)+'\n',encoding='utf-8')
final=OUT/'CyberTwin-AI-Actual-Site-Hindi.mp4'
run(['-f','concat','-safe','0','-i','site-concat.txt','-f','ffmetadata','-i','site-metadata.ffmeta',
     '-map','0:v:0','-map','0:a:0','-map_metadata','1','-map_chapters','1','-c','copy','-movflags','+faststart',final],'site-mux.log')
run(['-v','error','-xerror','-i',final,'-map','0:v:0','-map','0:a:0','-f','null','-'],'site-decode.log')
assert not (WORK/'site-decode.log').read_text().strip(),'Media decode errors'
(OUT/'Actual-Site-Hindi-Subtitles.srt').write_text('\n'.join(allsubs),encoding='utf-8')
(OUT/'Actual-Site-Hindi-Transcript.md').write_text('\n'.join(transcript),encoding='utf-8')
timing={'duration_seconds':round(offset,3),'chapters':chapters}
(OUT/'site-chapter-timing.json').write_text(json.dumps(timing,indent=2),encoding='utf-8')
for j,sec in enumerate([5,offset*.23,offset*.5,offset*.73,offset-8]):
    run(['-ss',str(sec),'-i',final,'-frames:v','1','-update','1',WORK/f'actual-preview-{j+1}.png'],f'actual-preview-{j+1}.log')
run(['-ss','5','-i',final,'-frames:v','1','-update','1',OUT/'actual-site-poster.jpg'],'site-poster.log')
report={'durationSeconds':round(offset,3),'resolution':'1920x1080','codec':'H.264/AAC','actualWebsiteScenes':len(script),
        'presentationSlidesUsed':0,'normalUserDataChanged':False,'recordingMethod':'Background Playwright video recording, as used for Anumitra',
        'editing':'Actual website motion slowed or sped slightly to fit Hindi narration; full viewport retained',
        'captions':'Hindi; timing estimated within each scene','pageErrors':recording['pageErrors'],'fullDecode':'PASS',
        'bytes':final.stat().st_size,'sha256':hashlib.sha256(final.read_bytes()).hexdigest(),'scenes':checks}
(OUT/'actual-site-validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k!='scenes'}),flush=True)
