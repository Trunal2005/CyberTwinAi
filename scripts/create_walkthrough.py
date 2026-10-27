"""Build the audience-facing Hindi walkthrough without changing application behavior.

Dependencies are isolated in .cache/video-deps; only narration text is sent to TTS.
No credentials, IP investigation records or private logs enter the narration.
"""
import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.cache' / 'video-deps'))
from gtts import gTTS
import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont

OUT = ROOT / 'deliverables' / 'video'
WORK = ROOT / '.cache' / 'walkthrough'
WORK.mkdir(parents=True, exist_ok=True)
CHAPTERS = json.loads((OUT / 'chapters.json').read_text(encoding='utf-8'))
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
W, H = 1920, 1080
BG, PANEL, BORDER = '#09111f', '#111f32', '#2a3c56'
WHITE, MUTED, CYAN, VIOLET, GREEN, RED = '#e7f0fa', '#9cacc3', '#51d8e2', '#ae95fa', '#65d4af', '#ff8d9c'


def font(size, bold=False, hindi=False):
    name = 'Nirmala.ttc' if hindi else ('segoeuib.ttf' if bold else 'segoeui.ttf')
    return ImageFont.truetype(str(Path('C:/Windows/Fonts') / name), size)


def wrap(draw, text, face, width):
    lines, line = [], ''
    for word in text.split():
        candidate = f'{line} {word}'.strip()
        if line and draw.textlength(candidate, font=face) > width:
            lines.append(line)
            line = word
        else:
            line = candidate
    if line:
        lines.append(line)
    return lines


def text(draw, xy, value, size=28, fill=WHITE, width=None, bold=False, hindi=False, spacing=12):
    face = font(size, bold, hindi)
    lines = wrap(draw, value, face, width) if width else [value]
    x, y = xy
    for line in lines:
        draw.text((x, y), line, font=face, fill=fill)
        y += size + spacing
    return y


def card(draw, xy, title, caption='', color=CYAN, width=320, height=100):
    x, y = xy
    draw.rounded_rectangle((x, y, x+width, y+height), 15, fill=PANEL, outline=BORDER, width=2)
    draw.rounded_rectangle((x, y+16, x+5, y+height-16), 2, fill=color)
    end = text(draw, (x+23,y+16), title, 25, color, width=width-42, bold=True, spacing=4)
    if caption:
        text(draw, (x+23,end+7), caption, 19, MUTED, width=width-42, spacing=4)


def arrow(draw, a, b, color=CYAN, width=4):
    draw.line([a,b], fill=color, width=width)
    angle = math.atan2(b[1]-a[1],b[0]-a[0])
    tip = [(b[0],b[1])]+[(b[0]-16*math.cos(angle+d),b[1]-16*math.sin(angle+d)) for d in (-.5,.5)]
    draw.polygon(tip, fill=color)


def diagram(draw, kind):
    if kind == 'architecture':
        boxes = [((1050,335),'React workspace','Authenticated browser',CYAN),((1450,335),'FastAPI','Validation + authorization',CYAN),
                 ((1050,545),'Analysis services','Rules / ML / NetworkX',VIOLET),((1450,545),'Database','Events / assets / audit',GREEN)]
        for pos,title,cap,color in boxes:
            card(draw,pos,title,cap,color,330,115)
        arrow(draw,(1380,390),(1440,390)); arrow(draw,(1610,450),(1610,535));arrow(draw,(1510,490),(1230,535),VIOLET);arrow(draw,(1380,600),(1440,600),GREEN)
        text(draw,(1080,735),'Local-first · persisted evidence · documented APIs',23,MUTED,width=710)
    elif kind in ('pipeline','flow','ips','safeguards'):
        labels = {
            'pipeline':[('Validate','IP, ports, timestamp'),('Analyze','Rules + model'),('Persist','Evidence + origin'),('Decide','Separate IPS policy')],
            'flow':[('OBSERVE','Collect a network event'),('EXPLAIN','Identify a suspicious signal'),('INVESTIGATE','Correlate source and target'),('DEFEND','Preview a controlled response')],
            'ips':[('IDS','Observe + explain a signal'),('POLICY','Threshold + administrator mode'),('EXCLUSIONS','Protected networks + allowlist'),('IPS','Simulate or verified lab adapter')],
            'safeguards':[('PREVIEW + CONFIRM','Administrator authorization'),('VALIDATE + PROTECT','Allowlist, management IPs, limits'),('EXECUTE + VERIFY','Adapter-specific action status'),('AUDIT + EXPIRE','Recovery and temporary lifetime')],
        }[kind]
        for i,(a,b) in enumerate(labels):
            card(draw,(1080,315+i*133),a,b,VIOLET if i%2 else CYAN,650,108)
            if i<3:arrow(draw,(1405,425+i*133),(1405,442+i*133),MUTED,3)
    elif kind=='modes':
        for i,(a,b,c) in enumerate([('SIMULATION','Generated local test observations',CYAN),('REPLAY','Imported historical records',VIOLET),('LIVE MONITORING','Fresh, explicitly configured sensor records',GREEN)]):
            card(draw,(1040,345+i*155),a,b,c,730,123)
    elif kind=='metrics':
        text(draw,(1100,310),'Actual / predicted class',26,MUTED)
        for (x,y),value,label,col in [((1080,390),'244','True negative',GREEN),((1430,390),'65','False positive',RED),((1080,590),'74','False negative',RED),((1430,590),'217','True positive',GREEN)]:
            draw.rounded_rectangle((x,y,x+310,y+170),17,fill=PANEL,outline=col,width=2)
            text(draw,(x+25,y+15),value,64,col,bold=True)
            text(draw,(x+25,y+111),label,23,MUTED)
        text(draw,(1090,790),'600 synthetic test rows · NOT live-network accuracy',23,VIOLET)
    elif kind=='network':
        positions={'Router':(1110,420),'Firewall':(1360,420),'Web':(1640,340),'User PC':(1640,650),'App':(1640,490),'Database':(1360,650)}
        links=[('Router','Firewall'),('Firewall','Web'),('Firewall','User PC'),('Web','App'),('Web','Database'),('App','Database'),('User PC','App')]
        for a,b in links:arrow(draw,positions[a],positions[b],'#456882',3)
        for name,(x,y) in positions.items():
            draw.rounded_rectangle((x-96,y-42,x+96,y+42),12,fill=PANEL,outline=VIOLET if name=='Web' else CYAN,width=2)
            text(draw,(x-77,y-16),name,24,WHITE,bold=True)
        text(draw,(1070,785),'Directed virtual access · not real attacker movement',23,MUTED)
    elif kind=='comparison':
        for x,value,label,col in [(1100,'22.3','BASELINE',VIOLET),(1500,'0','MODIFIED',GREEN)]:
            draw.rounded_rectangle((x,365,x+300,630),20,fill=PANEL,outline=col,width=3)
            text(draw,(x+25,395),label,23,col,bold=True)
            text(draw,(x+25,460),value,87,WHITE,bold=True)
        arrow(draw,(1415,510),(1485,510))
        card(draw,(1100,680),'Modeled changes','1 restricted link + 1 patched pivot',CYAN,700,105)
        text(draw,(1105,810),'Illustrative graph result—not measured network safety',22,MUTED)
    elif kind=='formula':
        draw.rounded_rectangle((1030,355,1795,590),20,fill=PANEL,outline=VIOLET,width=2)
        text(draw,(1060,380),'100 × reachable weighted vulnerability',31,WHITE,width=710,bold=True)
        draw.line((1060,462,1760,462),fill=VIOLET,width=3)
        text(draw,(1115,485),'total weighted capacity',34,VIOLET,bold=True)
        card(draw,(1055,650),'Interpretation depends on assumptions','Graph access, asset values and simplified patching',CYAN,720,128)
    elif kind=='ml':
        for i,(a,b) in enumerate([('Synthetic flows','2,400 rows · reproducible seed 42'),('Split before fitting','1,800 train / 600 test'),('Compare + evaluate','Random Forest / majority-class baseline'),('Persist + predict','Model artifact and measured test report')]):
            card(draw,(1050,315+i*132),a,b,VIOLET,715,110)
    elif kind=='rules':
        for i,(a,b) in enumerate([('AUTH-001','Reported authentication failures'),('SCAN-001','Destination-port diversity'),('RATE-001 / BURST-001','Unusual reported connection behavior'),('ENGINE-SIGNATURE','Signature evidence from integrated engine')]):
            card(draw,(1050,315+i*132),a,b,RED if i==0 else CYAN,715,110)
    elif kind=='ip':
        card(draw,(1060,345),'Observed source IP','Correlate evidence across events',CYAN,700,110)
        card(draw,(1060,505),'Target services + related assets','Ports, protocols, timestamps and analyst notes',VIOLET,700,120)
        card(draw,(1060,680),'IP address ≠ person identity','NAT / VPN / proxy / shared address / spoofing',RED,700,120)
    elif kind=='evidence':
        for i,(a,b) in enumerate([('Event evidence','Source → service · timestamp · origin'),('Detection reasoning','Rule result ≠ ML score ≠ enforcement'),('Analyst review','Investigating / resolved / false positive')]):
            card(draw,(1060,350+i*160),a,b,CYAN if i!=1 else VIOLET,700,125)
    elif kind=='security':
        for i,(a,b) in enumerate([('Authenticate','Salted passwords + expiring sessions'),('Authorize','Administrative data and enforcement APIs'),('Validate','Schemas, file limits and origin checks'),('Account for actions','Audits, confirmations and recovery')]):
            card(draw,(1050,315+i*132),a,b,GREEN,715,110)
    elif kind=='reports':
        for i,(a,b,c) in enumerate([('JSON','Full evidence and analysis snapshot',CYAN),('CSV','Event table with provenance labels',GREEN),('PDF','Paginated printable research report',VIOLET)]):
            card(draw,(1060,345+i*155),a,b,c,700,120)
    elif kind=='validation':
        card(draw,(1060,345),'40 automated tests','33 backend + 7 frontend in recorded validation',GREEN,700,125)
        card(draw,(1060,515),'Verified local workflow','Build, authentication, graph and report exports',CYAN,700,125)
        card(draw,(1060,685),'Research limitations','Synthetic ML · no real IPS validation on Windows',VIOLET,700,125)
    elif kind=='closing':
        card(draw,(1030,350),'OPEN THE PROJECT','http://127.0.0.1:8000/',CYAN,760,145)
        card(draw,(1030,545),'START THE LOCAL SERVER',r'.\scripts\start.ps1',GREEN,760,145)
        text(draw,(1050,745),'Localhost = this computer only',29,MUTED)
        text(draw,(1050,795),'Observe. Understand. Defend.',32,VIOLET,bold=True)


def slide(chapter,index,caption):
    im=Image.new('RGB',(W,H),BG)
    d=ImageDraw.Draw(im)
    for x in range(1000,W,48):
        for y in range(310,850,48):
            d.ellipse((x,y,x+2,y+2),fill='#1a2d43')
    text(d,(80,38),'CYBERTWIN AI  /  RESEARCH WALKTHROUGH',20,CYAN,bold=True)
    text(d,(1480,38),'AI NARRATION · HINDI',19,MUTED)
    text(d,(80,106),chapter['title'],57,WHITE,width=1760,bold=True,spacing=6)
    text(d,(82,202),chapter['subtitle'],25,MUTED,width=1750,spacing=6)
    d.line((80,270,1840,270),fill=BORDER,width=2)
    y=322
    for bullet in chapter['bullets']:
        d.rounded_rectangle((84,y+11,93,y+20),3,fill=CYAN)
        y=text(d,(113,y),bullet,28,WHITE,width=785,spacing=10)+26
    if chapter['kind'] in ('dashboard','intro'):
        screenshot=Image.open(ROOT/'docs/screenshots/overview.png').convert('RGB')
        screenshot=screenshot.crop((0,0,screenshot.width,min(screenshot.height,1030)))
        screenshot.thumbnail((870,530),Image.Resampling.LANCZOS)
        xx=1010+(830-screenshot.width)//2
        yy=315+(530-screenshot.height)//2
        im.paste(screenshot,(xx,yy))
        d.rounded_rectangle((xx-2,yy-2,xx+screenshot.width+2,yy+screenshot.height+2),8,outline=BORDER,width=2)
        text(d,(1080,820),'Application screenshot · simulation workspace',22,MUTED)
    else:
        diagram(d,chapter['kind'])
    d.rounded_rectangle((80,885,1840,1015),18,fill='#142338',outline=BORDER,width=2)
    caption_image=Image.open(caption_path(caption)).convert('RGBA')
    im.paste(caption_image,(105,902),caption_image)
    text(d,(80,1036),f'CHAPTER {index+1:02d} / {len(CHAPTERS):02d}',17,MUTED)
    text(d,(1340,1036),'Simulation-first · evidence-led defense',17,MUTED)
    d.rectangle((0,H-4,int(W*(index+1)/len(CHAPTERS)),H),fill=CYAN)
    return im


def audio_path(i):return WORK/f'chapter-{i+1:02d}.mp3'


POSTER_CAPTION='साइबर सुरक्षा को समझें। सबूत की जांच करें। डिफेंस को सुरक्षित मॉडल में परखें।'


def caption_path(value):
    return WORK/f'caption-{hashlib.sha256(value.encode()).hexdigest()[:16]}.png'


def prepare_captions():
    values={c for chapter in CHAPTERS for c in captions(chapter['narration'])}|{POSTER_CAPTION}
    manifest=WORK/'captions.json'
    manifest.write_text(json.dumps([{'text':v,'file':str(caption_path(v))} for v in sorted(values)],ensure_ascii=False),encoding='utf-8')
    subprocess.run(['powershell.exe','-NoProfile','-File',str(ROOT/'scripts/render_hindi_captions.ps1'),'-Manifest',str(manifest)],check=True)


def make_audio(i):
    path=audio_path(i)
    if path.exists() and path.stat().st_size>1000:return i
    for attempt in range(3):
        try:
            gTTS(CHAPTERS[i]['narration'],lang='hi',timeout=40).save(str(path))
            return i
        except Exception:
            if attempt==2:raise
            time.sleep(2+attempt)


def duration(path):
    p=subprocess.run([FFMPEG,'-hide_banner','-i',str(path)],capture_output=True,text=True)
    m=re.search(r'Duration: (\d+):(\d+):(\d+\.\d+)',p.stderr)
    if not m:raise RuntimeError(f'Cannot inspect audio {path.name}')
    return int(m[1])*3600+int(m[2])*60+float(m[3])


def captions(value):
    # Short caption groups synchronized proportionally within each narrated chapter.
    # This is an estimated caption timeline, not claimed word-level alignment.
    groups=[]
    for sentence in re.split(r'(?<=[।?!])\s+',value):
        current=''
        for word in sentence.split():
            if len(current)+len(word)>140:
                groups.append(current)
                current=word
            else:current=(current+' '+word).strip()
        if current:groups.append(current)
    return groups


def stamp(t,ms_separator=','):
    ms=round(t*1000);s,ms=divmod(ms,1000);m,s=divmod(s,60);h,m=divmod(m,60)
    return f'{h:02d}:{m:02d}:{s:02d}{ms_separator}{ms:03d}'


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--audio-only',action='store_true')
    parser.add_argument('--preview-only',action='store_true')
    args=parser.parse_args()
    prepare_captions()
    if args.preview_only:
        for i in [0,2,4,12,14,19]:
            slide(CHAPTERS[i],i,captions(CHAPTERS[i]['narration'])[0]).save(OUT/f'preview-{i+1:02d}.jpg',quality=90)
        print('Preview frames rendered',flush=True)
        return
    with ThreadPoolExecutor(max_workers=2) as executor:
        for task in as_completed([executor.submit(make_audio,i) for i in range(len(CHAPTERS))]):
            print(f'Narration {task.result()+1}/{len(CHAPTERS)} ready',flush=True)
    if args.audio_only:return
    parts=[];srt=[];timeline=[];offset=0
    transcript=['# CyberTwin AI — Hindi / Hinglish audience walkthrough','',
                'AI-generated narration; diagram-led presentation using the actual project. Caption timing is approximate.','']
    for i,chapter in enumerate(CHAPTERS):
        audio=audio_path(i);length=duration(audio)
        groups=captions(chapter['narration']);weight=sum(len(c) for c in groups)
        concat=['ffconcat version 1.0'];local=0
        for j,caption in enumerate(groups):
            seconds=length*len(caption)/weight
            frame=WORK/f'frame-{i:02d}-{j:02d}.jpg'
            slide(chapter,i,caption).save(frame,quality=90)
            concat += [f"file '{frame.as_posix()}'",f'duration {seconds:.6f}']
            srt += [str(len(srt)//4+1),f'{stamp(offset+local)} --> {stamp(offset+local+seconds)}',caption,'']
            local+=seconds
        concat += [f"file '{frame.as_posix()}'"]
        manifest=WORK/f'slides-{i:02d}.ffconcat';manifest.write_text('\n'.join(concat)+'\n',encoding='utf-8')
        part=WORK/f'part-{i:02d}.mp4'
        cmd=[FFMPEG,'-hide_banner','-loglevel','error','-y','-safe','0','-f','concat','-i',str(manifest),'-i',str(audio),
             '-vf','fps=12','-c:v','libx264','-preset','veryfast','-tune','stillimage','-crf','23','-pix_fmt','yuv420p',
             '-c:a','aac','-b:a','128k','-ar','44100','-ac','2','-t',f'{length:.3f}','-movflags','+faststart',str(part)]
        subprocess.run(cmd,check=True)
        parts.append(part)
        timeline.append({'chapter':i+1,'title':chapter['title'],'start_seconds':round(offset,3),'duration_seconds':length})
        transcript += [f"## {stamp(offset,'.')} — {chapter['title']}",'',chapter['narration'],'']
        offset+=length
        print(f'Encoded chapter {i+1}/{len(CHAPTERS)} ({length:.1f}s)',flush=True)
    manifest=WORK/'parts.ffconcat'
    manifest.write_text('ffconcat version 1.0\n'+'\n'.join(f"file '{p.as_posix()}'" for p in parts)+'\n',encoding='utf-8')
    destination=OUT/'CyberTwin-AI-Hindi-Walkthrough.mp4'
    subprocess.run([FFMPEG,'-hide_banner','-loglevel','error','-y','-safe','0','-f','concat','-i',str(manifest),'-c','copy','-movflags','+faststart',str(destination)],check=True)
    (OUT/'CyberTwin-AI-Hindi-Subtitles.srt').write_text('\n'.join(srt),encoding='utf-8')
    (OUT/'Hindi-Transcript.md').write_text('\n'.join(transcript),encoding='utf-8')
    (OUT/'chapter-timing.json').write_text(json.dumps({'duration_seconds':round(offset,3),'chapters':timeline},indent=2),encoding='utf-8')
    slide(CHAPTERS[0],0,POSTER_CAPTION).save(OUT/'poster.jpg',quality=92)
    print(f'COMPLETE: {destination.name} | {offset/60:.1f} minutes | {destination.stat().st_size/1024**2:.1f} MB',flush=True)


if __name__=='__main__':main()
