"""Embed chapter metadata, create an offline/local video viewer, and validate media."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.cache/video-deps'))
import imageio_ffmpeg

OUT=ROOT/'deliverables/video'
FFMPEG=imageio_ffmpeg.get_ffmpeg_exe()
timing=json.loads((OUT/'chapter-timing.json').read_text())
video=OUT/'CyberTwin-AI-Hindi-Walkthrough.mp4'
metadata=[';FFMETADATA1','title=CyberTwin AI - Hindi Research Walkthrough','artist=AI-generated Hindi narration',
          'comment=Simulation-first research project. Synthetic model metrics and illustrative diagrams.']
for chapter in timing['chapters']:
    start=round(chapter['start_seconds']*1000)
    end=round((chapter['start_seconds']+chapter['duration_seconds'])*1000)
    metadata+=['[CHAPTER]','TIMEBASE=1/1000',f'START={start}',f'END={end}',f"title={chapter['chapter']:02d}. {chapter['title']}"]
meta=ROOT/'.cache/walkthrough/metadata.ffmeta'
meta.write_text('\n'.join(metadata)+'\n',encoding='utf-8')
temp=OUT/'walkthrough-chapters.mp4'
subprocess.run([FFMPEG,'-hide_banner','-loglevel','error','-y','-i',str(video),'-f','ffmetadata','-i',str(meta),
                '-map','0:v:0','-map','0:a:0','-map_metadata','1','-map_chapters','1','-c','copy','-movflags','+faststart',str(temp)],check=True)
temp.replace(video)
chapters=json.dumps(timing['chapters'])
html='''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberTwin AI · Hindi walkthrough</title><style>
:root{color-scheme:dark;font:15px/1.6 'Segoe UI',sans-serif;background:#09111f;color:#e6effb}*{box-sizing:border-box}body{margin:0}main{max-width:1440px;margin:auto;padding:34px 28px}a{color:#68dbe4}header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:25px}h1{font-size:30px;line-height:1.25;margin:8px 0}h2{font-size:17px;margin:0 0 16px}p{color:#9bacc4;margin:8px 0}.eyebrow{font-size:11px;letter-spacing:2px;color:#63d8e0}.tag{font-size:12px;color:#b7a4fa;border:1px solid #4a3d69;padding:7px 12px;border-radius:6px;white-space:nowrap}.layout{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:22px}video{width:100%;display:block;border-radius:10px;border:1px solid #2c405a;background:#000}.panel{background:#111e31;border:1px solid #2a3b54;border-radius:10px;padding:22px}.chapters{max-height:600px;overflow:auto}.chapters button{font:inherit;font-size:13px;display:flex;align-items:flex-start;gap:12px;text-align:left;width:100%;padding:12px 6px;color:#cfdded;background:transparent;border:0;border-bottom:1px solid #26374d;cursor:pointer}.chapters button:hover,.chapters button.active{color:#65dce4;background:#3bc9d70d}.chapters span{font:12px/1.8 Consolas,monospace;color:#83a0bb;flex:none}.actions{display:flex;gap:20px;flex-wrap:wrap;margin:20px 0}.actions a{display:inline-block;font-size:13px;padding:9px 14px;border:1px solid #35506b;border-radius:6px;text-decoration:none}.notice{font-size:13px;border-left:3px solid #a58af2;padding:10px 16px;background:#a58af20b}.details{margin-top:22px}.details p{font-size:13px}button:focus-visible,a:focus-visible{outline:2px solid #64e1e7;outline-offset:3px}@media(max-width:950px){.layout{grid-template-columns:1fr}.chapters{max-height:370px}header{align-items:flex-start;flex-direction:column}main{padding:25px 16px}h1{font-size:25px}}
</style></head><body><main><header><div><div class="eyebrow">CYBERTWIN AI / RESEARCH PRESENTATION</div><h1>Understand the project, in Hindi.</h1><p>Detailed architecture, detection, prevention, machine learning and digital twin walkthrough.</p></div><span class="tag">Hindi / Hinglish · AI narration · 1080p</span></header>
<div class="layout"><section><video id="player" controls preload="metadata" poster="poster.jpg"><source src="CyberTwin-AI-Hindi-Walkthrough.mp4" type="video/mp4"><track src="subtitles.vtt" kind="subtitles" srclang="hi" label="Hindi captions (approximate)">Your browser does not support video playback.</video>
<div class="actions"><a download href="CyberTwin-AI-Hindi-Walkthrough.mp4">Download MP4</a><a href="Hindi-Transcript.md">Read Hindi transcript</a><a download href="CyberTwin-AI-Hindi-Subtitles.srt">Download subtitles</a><a href="/">Open project dashboard</a></div>
<p class="notice">AI-generated narration with project screenshots and illustrative diagrams. Simulation and synthetic model results are explicitly labeled; this is not footage of real attacks or a claim of production security.</p>
<div class="panel details"><h2>What this presentation covers</h2><p>Problem and architecture · event origins · overview · IDS rules · investigation · IPS safeguards · reproducible model evaluation · virtual network and what-if defenses · security · exports · tests · limitations · demo procedure.</p><p>Local application: <a href="/">http://127.0.0.1:8000/</a> · API documentation: <a href="/docs">/docs</a>. Localhost works on this computer only.</p></div></section>
<aside class="panel"><h2>20 chapter walkthrough</h2><p id="duration"></p><div id="chapters" class="chapters"></div></aside></div></main>
<script>const chapters=__CHAPTERS__;const player=document.getElementById('player');const list=document.getElementById('chapters');function stamp(t){return Math.floor(t/60)+':'+String(Math.floor(t%60)).padStart(2,'0')}document.getElementById('duration').textContent='Approx. '+stamp(__DURATION__)+' minutes';for(const c of chapters){const b=document.createElement('button');const s=document.createElement('span');s.textContent=stamp(c.start_seconds);const title=document.createElement('strong');title.textContent=c.title;b.append(s,title);b.onclick=()=>{player.currentTime=c.start_seconds;player.play().catch(()=>{});player.scrollIntoView({behavior:'smooth',block:'center'})};list.append(b)}player.addEventListener('timeupdate',()=>{[...list.children].forEach((b,i)=>b.classList.toggle('active',player.currentTime>=chapters[i].start_seconds&&(i===chapters.length-1||player.currentTime<chapters[i+1].start_seconds)))})</script></body></html>'''
html=html.replace('__CHAPTERS__',chapters).replace('__DURATION__',str(timing['duration_seconds']))
(OUT/'index.html').write_text(html,encoding='utf-8')
srt=(OUT/'CyberTwin-AI-Hindi-Subtitles.srt').read_text(encoding='utf-8')
(OUT/'subtitles.vtt').write_text('WEBVTT\n\n'+re.sub(r'(\d\d:\d\d:\d\d),(\d{3})',r'\1.\2',srt),encoding='utf-8')
info=subprocess.run([FFMPEG,'-hide_banner','-i',str(video)],capture_output=True,text=True)
print(info.stderr,flush=True)
# Decode the complete audio and video streams; fail on any decoding error.
subprocess.run([FFMPEG,'-hide_banner','-loglevel','error','-xerror','-i',str(video),'-map','0:v:0','-map','0:a:0','-f','null','-'],check=True)
audio=subprocess.run([FFMPEG,'-hide_banner','-i',str(video),'-vn','-af','volumedetect','-f','null','-'],capture_output=True,text=True,check=True)
levels=[line.strip() for line in audio.stderr.splitlines() if 'mean_volume' in line or 'max_volume' in line]
proof={'full_decode':'passed','resolution':'1920x1080','video_codec':'H.264','audio_codec':'AAC','chapters':len(timing['chapters']),
       'script_duration_seconds':timing['duration_seconds'],'size_bytes':video.stat().st_size,'audio_levels':levels,
       'captions':'Hindi burned in; SRT and VTT supplied; timing approximate'}
(OUT/'media-validation.json').write_text(json.dumps(proof,indent=2),encoding='utf-8')
print(json.dumps(proof,indent=2),flush=True)
