"""Prepare, narrate, encode and publish the updated actual-site Hinglish demo."""
from pathlib import Path
import hashlib,json,os,re,secrets,subprocess,sys,time

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'.cache/cn-site-video-20261029'
OUT=ROOT/'deliverables/video'
WORK.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(ROOT/'.cache/video-deps'))
SCRIPT=json.loads((OUT/'cn-site-narration.json').read_text(encoding='utf-8'))
FINAL=OUT/'CyberTwin-AI-CN-Site-Explanation-Hinglish.mp4'

def ff():
 import imageio_ffmpeg
 return imageio_ffmpeg.get_ffmpeg_exe()
def duration(p):
 r=subprocess.run([ff(),'-hide_banner','-i',str(p)],capture_output=True,text=True)
 m=re.search(r'Duration: (\d+):(\d+):(\d+\.\d+)',r.stderr)
 if not m:raise RuntimeError(f'Cannot inspect {p.name}')
 return int(m[1])*3600+int(m[2])*60+float(m[3])
def run(args,log):
 with (WORK/log).open('w',encoding='utf-8') as f:
  subprocess.run([ff(),'-hide_banner','-y',*map(str,args)],cwd=WORK,stdout=f,stderr=f,check=True)
def stamp(t):
 ms=round(t*1000);s,ms=divmod(ms,1000);m,s=divmod(s,60);h,m=divmod(m,60)
 return f'{h:02d}:{m:02d}:{s:02d},{ms:03d}'
def prepare():
 db=WORK/'demo.db'
 if db.exists():print('Isolated recording database retained.');return
 credentials={'username':'presentation_admin','password':secrets.token_urlsafe(24)}
 (WORK/'credentials.json').write_text(json.dumps(credentials),encoding='utf-8')
 os.environ.update(DATABASE_URL='sqlite:///'+db.as_posix(),MODEL_PATH=(ROOT/'data/model.joblib').as_posix(),FIREWALL_ADAPTER='simulated',REAL_ENFORCEMENT='false',SURICATA_EVE_PATH='',SURICATA_LIVE_CONFIRMED='false',CORS_ORIGINS='http://127.0.0.1:8006')
 subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True)
 sys.path.insert(0,str(ROOT))
 from backend.db import SessionLocal,User
 from backend.security import password_hash
 from backend.seed import seed_topology,seed_events,extend_cn_topology
 with SessionLocal() as s:
  s.add(User(username=credentials['username'],password_hash=password_hash(credentials['password']),role='admin'));s.commit()
  seed_topology(s);extend_cn_topology(s);seed_events(s)
 print('Fresh disposable presentation database ready; primary database unchanged.',flush=True)
def narrate():
 # Offline synthesis only: neither text nor audio is sent to an external API.
 import wave
 sys.path.insert(0,str(ROOT/'.cache/local-tts'))
 from piper import PiperVoice,SynthesisConfig
 voice=PiperVoice.load(WORK/'voice/hi_IN-pratham-medium.onnx')
 synthesis=SynthesisConfig(length_scale=1.03,noise_scale=.55,noise_w_scale=.7)
 jobs=[]
 for ch in SCRIPT:
  for j,b in enumerate(ch['beats'],1):jobs.append((f"{ch['chapter']:02d}-{j:02d}",b))
 def work(job):
  key,b=job;p=WORK/f'audio-{key}.mp3';hashfile=WORK/f'audio-{key}.sha256';digest=hashlib.sha256(b['text'].encode()).hexdigest()
  digest=hashlib.sha256(('piper-pratham-1.03:'+b['text']).encode()).hexdigest()
  if not(p.exists() and p.stat().st_size>1000 and hashfile.exists() and hashfile.read_text()==digest):
   wav=WORK/f'audio-{key}.wav'
   with wave.open(str(wav),'wb') as stream:voice.synthesize_wav(b['text'],stream,syn_config=synthesis)
   run(['-i',wav,'-c:a','libmp3lame','-b:a','160k',p],f'audio-{key}.log')
   hashfile.write_text(digest)
  return key,{'seconds':duration(p),'action':b['action'],'engine':'offline Piper Hindi pratham'}
 result={}
 for job in jobs:
  key,data=work(job);result[key]=data;print(f'Local Hindi narration {key} ready: {data["seconds"]:.1f}s',flush=True)
 (WORK/'audio-timing.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
 print(f'Total narration: {sum(v["seconds"] for v in result.values())/60:.1f} minutes',flush=True)
def encode(partial=False):
 rec=json.loads((WORK/'recording.json').read_text());assert not rec['pageErrors']
 lookup={b['key']:b for b in rec['beats']};totalbeats=sum(len(c['beats']) for c in SCRIPT)
 if not partial:assert len(lookup)==totalbeats
 offset=0;chapters=[];subs=[];parts=[];transcript=['# CyberTwin AI — updated CN website explanation in Hinglish','','Actual running application, fictional lab data, AI-generated Hindi/Hinglish narration.','']
 for ch in SCRIPT:
  if any(f"{ch['chapter']:02d}-{j:02d}" not in lookup for j in range(1,len(ch['beats'])+1)):
   if partial:break
   raise RuntimeError('Incomplete website recording')
  start=offset
  for j,b in enumerate(ch['beats'],1):
   key=f"{ch['chapter']:02d}-{j:02d}";r=lookup[key];audio=WORK/f'audio-{key}.mp3';length=duration(audio);target=length+.45
   stem=f'part-{key}';raw=WORK/f"chapter-{ch['chapter']:02d}.webm"
   # Retain actual website motion. Only tiny timing adjustment if actions ran long.
   speed=target/r['duration'];vf=f"trim=start={r['start']:.4f}:duration={r['duration']:.4f},setpts=(PTS-STARTPTS)*{speed:.8f},fps=20,scale=1728:1080,pad=1920:1080:96:0:black,tpad=stop_mode=clone:stop_duration=0.5"
   cache=WORK/f'{stem}.sha256';digest=hashlib.sha256(json.dumps({'clip':r,'raw_size':raw.stat().st_size,'raw_time':raw.stat().st_mtime_ns,'audio':hashlib.sha256(audio.read_bytes()).hexdigest(),'filter':vf,'revision':1},sort_keys=True).encode()).hexdigest()
   if not ((WORK/f'{stem}.mp4').exists() and cache.exists() and cache.read_text()==digest):
    run(['-i',raw,'-i',audio,'-vf',vf,'-af','loudnorm=I=-18:TP=-1.5:LRA=11,apad=pad_dur=0.6','-t',f'{target:.3f}','-c:v','libx264','-threads','4','-preset','veryfast','-crf','21','-pix_fmt','yuv420p','-c:a','aac','-b:a','128k','-ar','44100','-ac','2','-movflags','+faststart',WORK/f'{stem}.mp4'],f'{stem}.log')
    cache.write_text(digest)
   chunks=[]
   for sentence in re.split(r'(?<=[।.!?])\s+',b['text']):
    words=sentence.split()
    while words:chunks.append(' '.join(words[:14]));words=words[14:]
   weight=sum(len(x) for x in chunks);elapsed=0
   for caption in chunks:
    begin=elapsed;elapsed+=length*len(caption)/weight;subs.append((offset+begin,offset+elapsed,caption))
   parts.append(f"file '{stem}.mp4'")
   transcript += [f"### {stamp(offset).replace(',','.')}",'',b['text'],'']
   offset+=target;print(f'Encoded actual-site beat {key}',flush=True)
  chapters.append({'chapter':ch['chapter'],'title':ch['title'],'start_seconds':round(start,3),'duration_seconds':round(offset-start,3)})
 if partial:
  print(f'Prepared {len(parts)} recorded video parts for final assembly.',flush=True);return
 (WORK/'concat.txt').write_text('\n'.join(parts),encoding='utf-8')
 meta=[';FFMETADATA1','title=CyberTwin AI - CN Project Website Explanation in Hinglish','artist=AI Hindi narration','comment=Actual running website with isolated simulation and replay data.']
 for ch in chapters:meta+=['[CHAPTER]','TIMEBASE=1/1000',f"START={round(ch['start_seconds']*1000)}",f"END={round((ch['start_seconds']+ch['duration_seconds'])*1000)}",f"title={ch['chapter']:02d}. {ch['title']}"]
 (WORK/'metadata.txt').write_text('\n'.join(meta)+'\n',encoding='utf-8')
 run(['-f','concat','-safe','0','-i','concat.txt','-f','ffmetadata','-i','metadata.txt','-map','0:v:0','-map','0:a:0','-map_metadata','1','-map_chapters','1','-c','copy','-movflags','+faststart',FINAL],'mux.log')
 run(['-v','error','-xerror','-i',FINAL,'-map','0:v:0','-map','0:a:0','-f','null','-'],'decode.log');assert not (WORK/'decode.log').read_text().strip()
 srt='\n'.join(f'{i}\n{stamp(a)} --> {stamp(z)}\n{text}\n' for i,(a,z,text) in enumerate(subs,1))
 (OUT/'CN-Site-Hinglish-Subtitles.srt').write_text(srt,encoding='utf-8')
 (OUT/'cn-site-subtitles.vtt').write_text('WEBVTT\n\n'+re.sub(r'(\d\d:\d\d:\d\d),(\d{3})',r'\1.\2',srt),encoding='utf-8')
 (OUT/'CN-Site-Hinglish-Transcript.md').write_text('\n'.join(transcript),encoding='utf-8')
 (OUT/'cn-site-chapters.json').write_text(json.dumps({'duration_seconds':round(offset,3),'chapters':chapters},indent=2),encoding='utf-8')
 run(['-ss','4','-i',FINAL,'-frames:v','1','-update','1',OUT/'cn-site-poster.jpg'],'poster.log')
 for i,t in enumerate([5,offset*.15,offset*.34,offset*.56,offset*.75,offset*.9],1):run(['-ss',str(t),'-i',FINAL,'-frames:v','1','-update','1',WORK/f'qa-{i}.png'],f'qa-{i}.log')
 report={'duration_seconds':round(offset,3),'resolution':'1920x1080','codec':'H.264/AAC','chapters':len(chapters),'actual_website_beats':totalbeats,'slides':0,'narration_engine':'Piper Hindi pratham, offline','narration_sent_to_external_service':False,'full_decode':'PASS','page_errors':rec['pageErrors'],'main_database_changed':False,'simulated_firewall':True,'bytes':FINAL.stat().st_size,'sha256':hashlib.sha256(FINAL.read_bytes()).hexdigest()}
 (OUT/'cn-site-validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report),flush=True)
def publish():
 timing=json.loads((OUT/'cn-site-chapters.json').read_text());source=(OUT/'site.html').read_text(encoding='utf-8')
 source=source.replace('CyberTwin-AI-Actual-Site-Hindi.mp4',FINAL.name).replace('actual-site-poster.jpg','cn-site-poster.jpg').replace('actual-site-subtitles.vtt','cn-site-subtitles.vtt').replace('Actual-Site-Hindi-Transcript.md','CN-Site-Hinglish-Transcript.md').replace('Actual-Site-Hindi-Subtitles.srt','CN-Site-Hinglish-Subtitles.srt')
 webm=FINAL.with_suffix('.webm')
 if webm.exists() and webm.name not in source:
  source=source.replace(f'<source src="{FINAL.name}" type="video/mp4">',f'<source src="{FINAL.name}" type=\'video/mp4; codecs="avc1.640028, mp4a.40.2"\'><source src="{webm.name}" type=\'video/webm; codecs="vp9, opus"\'>')
 source=source.replace('CyberTwin AI: actual website walkthrough','CyberTwin AI: CN project explained on the website').replace('Short project introduction, followed by actual website navigation, clicks, scrolling and demos in Hindi.','Simple Hinglish explanation: PCAP, IDS evidence, investigation, controlled prevention, digital twin and reports.').replace('13 actual website chapters',f"{len(timing['chapters'])} actual website chapters").replace('Hindi captions (approximate)','Hindi captions (approximate; optional)')
 source=re.sub(r'const chapters=.*?;const player=',lambda m:'const chapters='+json.dumps(timing['chapters'])+';const player=',source,flags=re.S)
 source=re.sub(r'stamp\(\d+(?:\.\d+)?\)\+',f"stamp({timing['duration_seconds']})+",source)
 for name in ['cn-demo.html','site.html','index.html']:(OUT/name).write_text(source,encoding='utf-8')
 (OUT/'CN_VIDEO_README.md').write_text(f'''# Updated CyberTwin AI CN website explanation

Video: `{FINAL.name}`. Duration: {timing['duration_seconds']/60:.1f} minutes. 1080p H.264/AAC with locally generated Hindi/Hinglish narration, 16 chapters and optional captions. No narration text or audio was sent to an external service.

Actual running application footage with clicks, scrolling, PCAP upload, SCAN-001 evidence, review, linked flow journey, IP notes, manual policy, simulated prevention, block removal, observed replay, before/after twin comparison, model prediction, monitoring and PDF export. Authentication stays off camera.

All recording actions use a disposable database under `.cache/cn-site-video-20261029/`; the primary database and firewall are unchanged. Replay and simulation are explicitly explained. Synthetic model metrics and modeled defense outcomes are not real-world performance claims. Captions use approximate within-beat timing.

Watch at http://127.0.0.1:8000/walkthrough/cn-demo.html while the application server is running. The default walkthrough also opens this updated version.

Reproduce: `python scripts/build_cn_video.py prepare`, `python scripts/build_cn_video.py narrate`, `node scripts/record_cn_video.mjs`, `python scripts/build_cn_video.py encode`, `python scripts/build_cn_video.py publish`. Optional media dependencies live in `.cache/video-deps` and Playwright in `tools/video`.

Offline speech: Piper 1.8.0 (https://github.com/OHF-Voice/piper1-gpl), GPL-3.0-or-later engine, installed separately under `.cache/local-tts`. Hindi voice: Pratham medium, trained by PravalX using AI4Bharat indicnlp_corpus. Voice card: https://huggingface.co/rhasspy/piper-voices/blob/main/hi/hi_IN/pratham/medium/MODEL_CARD . The voice card identifies the dataset license as CC-BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/). This is a noncommercial educational project demonstration. Model files and licenses remain with the local voice cache and are not bundled into the application. Download the public model and configuration into `.cache/cn-site-video-20261029/voice/` before local narration.
''',encoding='utf-8')
 (OUT/'README.md').write_text(f'''# CyberTwin AI — website explanation in Hindi / Hinglish

Current video: [{FINAL.name}]({FINAL.name}), {timing['duration_seconds']/60:.1f} minutes, 1080p, 16 chapters.

Watch at http://127.0.0.1:8000/walkthrough/cn-demo.html while the app server is running. The default `/walkthrough/` viewer also opens this version.

The footage shows the actual running website: PCAP upload, protocol filtering, port-scan evidence, source investigation, approval, simulated prevention, network replay, defense comparison, AI evaluation/prediction, monitoring and PDF export. Hindi/Hinglish voiceover is generated locally with Piper; narration text and audio are not uploaded to a service.

Files: [transcript](CN-Site-Hinglish-Transcript.md), [subtitles](CN-Site-Hinglish-Subtitles.srt), [chapters](cn-site-chapters.json), [validation](cn-site-validation.json), [reproduction and voice credits](CN_VIDEO_README.md).

All demo actions use a disposable database. Actual packet blocking is not claimed. Model results use the documented synthetic benchmark.

Earlier recordings remain as archives: `CyberTwin-AI-Actual-Site-Hindi.mp4` (pre-CN site walkthrough) and `CyberTwin-AI-Hindi-Walkthrough.mp4` (slide presentation).
''',encoding='utf-8')
 oldreadme=OUT/'ACTUAL_SITE_README.md'
 if oldreadme.exists():
  old=oldreadme.read_text(encoding='utf-8')
  if not old.startswith('> Archived'):oldreadme.write_text('> Archived pre-CN recording. The current video and viewer are documented in [README.md](README.md).\n\n'+old,encoding='utf-8')
 print('Updated local video viewer published.',flush=True)
def webm():
 target=FINAL.with_suffix('.webm')
 run(['-i',FINAL,'-c:v','libvpx-vp9','-deadline','realtime','-cpu-used','8','-row-mt','1','-threads','4','-crf','30','-b:v','0','-c:a','libopus','-b:a','96k','-map_chapters','0','-progress',WORK/'webm-progress.txt','-stats_period','5','-nostats',target],'webm-encode.log')
 print(f'Browser-compatible WebM ready: {target.stat().st_size:,} bytes',flush=True)
if __name__=='__main__':
 {'prepare':prepare,'narrate':narrate,'parts':lambda:encode(partial=True),'encode':encode,'publish':publish,'webm':webm}[sys.argv[1]]()
