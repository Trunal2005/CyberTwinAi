// Real application recording, with each action timed to its narration beat.
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const work=path.resolve(root,process.argv.find(a=>a.startsWith('--work='))?.slice(7)||'.cache/cn-site-video-20261029');
assert.ok(work.startsWith(path.join(root,'.cache')+path.sep));
const port=Number(process.argv.find(a=>a.startsWith('--port='))?.split('=')[1]||8006);
assert.ok([8006,8007].includes(port));
const origin=`http://127.0.0.1:${port}`;
const require=createRequire(path.join(root,'tools/video/package.json'));
const {chromium,request,expect}=require('@playwright/test');
const script=JSON.parse(fs.readFileSync(path.join(root,'deliverables/video/cn-site-narration.json'),'utf8'));
const audio=JSON.parse(fs.readFileSync(path.join(work,'audio-timing.json'),'utf8'));
const credentials=JSON.parse(fs.readFileSync(path.join(work,'credentials.json'),'utf8'));
const env={...process.env,DATABASE_URL:'sqlite:///'+path.join(work,'demo.db').replaceAll('\\','/'),MODEL_PATH:path.join(root,'data/model.joblib'),FIREWALL_ADAPTER:'simulated',REAL_ENFORCEMENT:'false',SURICATA_EVE_PATH:'',SURICATA_LIVE_CONFIRMED:'false',CORS_ORIGINS:origin};
assert.ok(env.DATABASE_URL.includes('/.cache/cn-site-video-20261029/'));
fs.mkdirSync(path.join(work,'raw'),{recursive:true});
const log=fs.openSync(path.join(work,'server-private.log'),'a');
const python=process.env.CYBERTWIN_PYTHON||path.join(root,process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python');
const server=spawn(python,['-m','uvicorn','backend.main:app','--host','127.0.0.1','--port',String(port),'--no-access-log'],{cwd:root,env,windowsHide:true,stdio:['ignore',log,log]});fs.closeSync(log);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const resume=Number(process.argv.find(a=>a.startsWith('--resume='))?.split('=')[1]||1);
const only=Number(process.argv.find(a=>a.startsWith('--only='))?.split('=')[1]||0);
const manifest=path.join(work,'recording.json');
const beats=resume>1&&fs.existsSync(manifest)?JSON.parse(fs.readFileSync(manifest,'utf8')).beats.filter(b=>b.chapter<resume):[];
const pageErrors=[];
let browser,client;
const hover=async(p,l)=>{await l.scrollIntoViewIfNeeded();const b=await l.boundingBox();if(b)await p.mouse.move(b.x+b.width/2,b.y+b.height/2,{steps:18});await sleep(500)};
const click=async(p,l)=>{await hover(p,l);await l.click();await sleep(600)};
const focus=async(p,l)=>{await l.scrollIntoViewIfNeeded();await hover(p,l);await sleep(500)};
const wheel=async(p,y)=>{await p.mouse.move(1270,650,{steps:12});await p.mouse.wheel(0,y);await sleep(1000)};
const top=async(p)=>wheel(p,-8000);
const button=(p,name)=>p.getByRole('button',{name,exact:true});
const scanRow=p=>p.getByRole('row').filter({hasText:'192.0.2.44:46007'});
async function scanFilters(p){await p.getByLabel('origin',{exact:true}).selectOption('replay');await p.getByLabel('Source IP',{exact:true}).fill('192.0.2.44');await expect(scanRow(p)).toBeVisible();}
async function scanJourney(p){await scanFilters(p);await click(p,scanRow(p).getByRole('button',{name:'Inspect flow'}));await expect(p.getByRole('dialog',{name:'Network flow journey'})).toBeVisible();await expect(p.locator('.flow-decision').first()).toBeVisible();}
const actions={
 intro:async p=>{await hover(p,p.getByRole('heading',{name:'Security overview',exact:true}));await sleep(5000);await hover(p,p.locator('nav').getByRole('button',{name:'Network Digital Twin',exact:true}));},
 introFlow:async p=>{for(const name of ['PCAP & Traffic Analysis','Threat Detection','IP Investigation','Blocklist','Network Digital Twin','AI Insights']){await hover(p,p.locator('nav').getByRole('button',{name,exact:true}));await sleep(1600)}},
 overviewTop:async p=>{await wheel(p,320);await sleep(4500);await wheel(p,300);},
 overviewOrigins:async p=>{await top(p);await hover(p,p.getByRole('heading',{name:'Security overview',exact:true}));await sleep(5000);await wheel(p,570);await sleep(5000);await top(p);},
 upload:async p=>{await hover(p,p.getByText('Upload capture or supported logs',{exact:true}));await sleep(1800);await p.getByLabel('Upload capture or logs',{exact:true}).setInputFiles(path.join(root,'samples/cn-demo.pcap'));await expect(p.getByText(/Offline replay stored:/)).toBeVisible();await sleep(1200);},
 captureMetrics:async p=>{await p.getByLabel('origin',{exact:true}).selectOption('replay');await sleep(1200);await focus(p,p.locator('.traffic-metrics'));await expect(p.locator('.traffic-metrics')).toContainText('13');await sleep(5000);await hover(p,p.locator('.traffic-metrics').getByText('Matching flows',{exact:true}));await sleep(2000);await hover(p,p.locator('.traffic-metrics').getByText('Known packets',{exact:true}));},
 udp:async p=>{await p.getByLabel('origin',{exact:true}).selectOption('replay');await p.getByLabel('protocol',{exact:true}).selectOption('UDP');await sleep(800);await focus(p,p.getByRole('table'));await expect(p.getByRole('table')).toContainText('UDP');await sleep(5000);await click(p,p.getByRole('button',{name:'Inspect flow',exact:true}).first());await focus(p,p.getByRole('heading',{name:'Observed endpoints and modeled journey',exact:true}));},
 icmp:async p=>{await click(p,button(p,'Close'));await top(p);await p.getByLabel('protocol',{exact:true}).selectOption('ICMP');await sleep(800);await focus(p,p.getByRole('table'));await expect(p.getByRole('table')).toContainText('2001:db8');await click(p,button(p,'Inspect flow').first());await focus(p,p.getByRole('dialog').getByText('IP version',{exact:true}));},
 findScan:async p=>{await p.getByLabel('Filter provenance',{exact:true}).selectOption('replay');await p.getByLabel('Search events',{exact:true}).fill('192.0.2.44');await expect(p.getByRole('table')).toContainText('Port scan indicator');await sleep(2000);await click(p,p.getByRole('button',{name:/^View event /}).first());await expect(p.getByRole('dialog')).toContainText('SCAN-001');await focus(p,p.getByRole('heading',{name:'Detection evidence',exact:true}));},
 reviewScan:async p=>{await focus(p,p.getByRole('dialog').getByText('Rule risk',{exact:true}));await sleep(4000);await p.getByRole('dialog').locator('select').selectOption('investigating');await focus(p,button(p,'Save review'));await sleep(2000);await click(p,button(p,'Save review'));},
 flowOpen:async p=>{await scanJourney(p);await focus(p,p.getByRole('heading',{name:'Observed endpoints and modeled journey',exact:true}));},
 flowTimeline:async p=>{await focus(p,p.getByRole('heading',{name:'IDS and IPS action timeline',exact:true}));await sleep(6500);await focus(p,p.getByRole('heading',{name:'Supporting model result',exact:true}));},
 investigate:async p=>{await p.getByLabel('IP to investigate',{exact:true}).fill('192.0.2.44');await click(p,button(p,'Investigate IP'));await expect(p.getByRole('heading',{name:'Source event history',exact:true})).toBeVisible();await hover(p,p.getByText('Highest rule risk',{exact:true}));await sleep(3500);await focus(p,p.getByRole('heading',{name:'Source event history',exact:true}));},
 note:async p=>{await p.getByLabel('Evidence and context',{exact:true}).fill('Owned PCAP replay: eight distinct destination ports on one target within 60 seconds. SCAN-001 reviewed; retain source context and origin labels.');await focus(p,p.getByRole('heading',{name:'Investigation notes',exact:true}));await sleep(3000);await click(p,button(p,'Save note'));await sleep(1500);await focus(p,p.getByRole('heading',{name:'Investigation notes',exact:true}));},
 settingsExplain:async p=>{await focus(p,p.getByRole('heading',{name:'Integration status',exact:true}));await sleep(6000);await focus(p,p.getByRole('heading',{name:'Enforcement policy',exact:true}));},
 manualPolicy:async p=>{await p.getByLabel('Operating mode').selectOption('manual');await p.getByLabel('Automatic rule-risk threshold',{exact:true}).fill('70');await p.getByLabel('Default block duration (minutes)',{exact:true}).fill('5');await sleep(1500);await click(p,button(p,'Preview policy change'));await sleep(4500);await click(p,button(p,'Confirm policy'));await focus(p,p.getByRole('heading',{name:'Audit trail',exact:true}));},
 preventionPreview:async p=>{await scanJourney(p);await p.getByLabel('Block reason',{exact:true}).fill('Owned PCAP replay: SCAN-001 evidence reviewed; temporary simulated lab action.');await click(p,button(p,'Preview prevention'));await focus(p,button(p,'Confirm temporary block'));},
 preventionConfirm:async p=>{await click(p,button(p,'Confirm temporary block'));await expect(p.getByText('Prevention outcome recorded',{exact:true})).toBeVisible();await focus(p,p.getByRole('heading',{name:'IDS and IPS action timeline',exact:true}));const result=p.getByRole('dialog').getByText(/SIMULATED — NO REAL PACKETS WERE BLOCKED/).last();await expect(result).toBeAttached();await focus(p,result);},
 blocks:async p=>{await expect(button(p,'Remove').first()).toBeVisible();await focus(p,p.getByRole('table'));await sleep(6500);await click(p,button(p,'Remove').first());await sleep(3000);await click(p,button(p,'Confirm removal'));await sleep(1200);await focus(p,p.getByRole('table'));},
 observed:async p=>{await click(p,button(p,'Observed traffic'));await p.getByLabel('Provenance').selectOption('replay');await p.getByLabel('Speed',{exact:true}).selectOption('0.5');await click(p,button(p,'Replay stored observations'));await focus(p,p.locator('.react-flow').first());await sleep(5000);},
 observedInspect:async p=>{if(await button(p,'Pause').isVisible())await click(p,button(p,'Pause'));await p.getByLabel('Flow replay timeline',{exact:true}).fill('10');await focus(p,p.locator('.react-flow').first());await sleep(4000);await click(p,button(p,'Inspect selected flow'));await focus(p,p.getByRole('heading',{name:'IDS and IPS action timeline',exact:true}));},
 baseline:async p=>{await click(p,button(p,'Run defense comparison'));await sleep(1000);await wheel(p,720);await sleep(5000);await wheel(p,390);},
 defenses:async p=>{await top(p);await p.getByRole('checkbox',{name:'Application server Vulnerability 6/10',exact:true}).check();await p.getByRole('checkbox',{name:'Public web server Research database Baseline allows access',exact:true}).check();await click(p,button(p,'Run defense comparison'));await wheel(p,720);await sleep(6000);await wheel(p,390);},
 aiMetrics:async p=>{await hover(p,p.getByText('F1 score',{exact:true}));await sleep(4500);await focus(p,p.getByRole('heading',{name:'Baseline comparison & evaluation design',exact:true}));},
 aiMatrix:async p=>{await focus(p,p.getByRole('heading',{name:'Confusion matrix',exact:true}));await hover(p,p.locator('.matrix'));},
 aiPredict:async p=>{await focus(p,p.getByRole('heading',{name:'Try a flow prediction',exact:true}));await sleep(4000);await click(p,button(p,'Predict flow'));await focus(p,p.getByText(/Model score:/).first());},
 monitorStart:async p=>{await click(p,button(p,'Start monitoring'));await sleep(1200);await click(p,p.getByRole('dialog').getByRole('button',{name:'Start monitoring',exact:true}));await sleep(7000);await wheel(p,300);},
 monitorStop:async p=>{await top(p);await click(p,button(p,'Stop monitoring'));await sleep(1800);await click(p,p.getByRole('dialog').getByRole('button',{name:'Stop monitoring',exact:true}));await wheel(p,280);},
 report:async p=>{await sleep(2500);const promise=p.waitForEvent('download');await click(p,p.getByRole('button',{name:/PDF report/}));const dl=await promise;await dl.saveAs(path.join(work,'demo-evidence-report.pdf'));await sleep(2000);await wheel(p,430);await click(p,p.getByText('Inspect report JSON',{exact:true}));await wheel(p,220);},
 stack:async p=>{await wheel(p,430);await sleep(6000);await top(p);await hover(p,p.locator('nav').getByRole('button',{name:'AI Insights',exact:true}));},
 closing:async p=>{await top(p);for(const name of ['PCAP & Traffic Analysis','Threat Detection','Network Digital Twin','Reports']){await hover(p,p.locator('nav').getByRole('button',{name,exact:true}));await sleep(1800)}await hover(p,p.getByRole('heading',{name:'Security overview',exact:true}));}
};
try{
 let ready=false;for(let i=0;i<150;i++){try{if((await fetch(origin+'/api/health')).ok){ready=true;break}}catch{}await sleep(200)}assert.ok(ready,'Disposable server did not start');
 client=await request.newContext({baseURL:origin});const login=await client.post('/api/auth/login',{data:credentials});assert.equal(login.status(),200);
 const state=await client.storageState();const status=await(await client.get('/api/status')).json();assert.equal(status.adapter,'simulated');assert.equal(status.enforcement_enabled,false);
 await client.post('/api/monitor',{data:{running:false,mode:'simulation'}});
 if(resume===9){const active=await(await client.get('/api/blocks?q=192.0.2.44&state=active')).json();for(const b of active){assert.equal(b.adapter,'simulated');assert.equal((await client.delete(`/api/blocks/${b.id}?confirmed=true`)).status(),200)}}
 browser=await chromium.launch({headless:true});
 for(const ch of script){
  if(ch.chapter<resume||(only&&ch.chapter!==only))continue;
  const context=await browser.newContext({storageState:state,viewport:{width:1440,height:900},deviceScaleFactor:1,reducedMotion:'reduce',acceptDownloads:true,recordVideo:{dir:path.join(work,'raw'),size:{width:1440,height:900}}});
  await context.route('**/*',r=>new URL(r.request().url()).origin===origin?r.continue():r.abort());
  await context.addInitScript(()=>document.addEventListener('DOMContentLoaded',()=>{const cursor=document.createElement('div');cursor.style.cssText='position:fixed;width:17px;height:22px;background:white;clip-path:polygon(0 0,0 100%,32% 75%,57% 100%,75% 88%,50% 62%,94% 62%);filter:drop-shadow(1px 1px 2px black);pointer-events:none;z-index:2147483647;left:-40px;top:-40px';document.body.append(cursor);document.addEventListener('pointermove',e=>{cursor.style.left=e.clientX+'px';cursor.style.top=e.clientY+'px'});document.addEventListener('pointerdown',e=>{const ring=document.createElement('div');ring.style.cssText=`position:fixed;left:${e.clientX-17}px;top:${e.clientY-17}px;width:34px;height:34px;border:3px solid #51d8e2;border-radius:50%;pointer-events:none;z-index:2147483646`;document.body.append(ring);setTimeout(()=>ring.remove(),550)})}));
  const born=Date.now();const p=await context.newPage();p.on('pageerror',e=>{pageErrors.push({chapter:ch.chapter,error:e.message});console.error('Website page error:',e.message)});
  await p.goto(origin+'/#'+encodeURIComponent(ch.page));
  try{await expect(p.locator('h1')).toBeVisible({timeout:30000})}catch(e){await p.screenshot({path:path.join(work,`failure-start-${ch.chapter}.png`)});throw e}
  await sleep(1800);
  if(ch.chapter===12)await click(p,button(p,'Scenario'));
  for(let j=0;j<ch.beats.length;j++){
   const b=ch.beats[j],key=`${String(ch.chapter).padStart(2,'0')}-${String(j+1).padStart(2,'0')}`,start=(Date.now()-born)/1000;
   console.log(`Recording ${key}: ${ch.title} / ${b.action}`,true);
   try{assert.ok(actions[b.action]);await actions[b.action](p)}catch(e){await p.screenshot({path:path.join(work,`failure-${key}.png`)});throw e}
   const elapsed=(Date.now()-born)/1000-start;const hold=audio[key].seconds+.6-elapsed;if(hold>0)await sleep(hold*1000);
   const end=(Date.now()-born)/1000;beats.push({key,chapter:ch.chapter,action:b.action,start,duration:end-start});
   await p.screenshot({path:path.join(work,`beat-${key}.png`)});
  }
  const video=p.video();await context.close();await video.saveAs(path.join(work,`chapter-${String(ch.chapter).padStart(2,'0')}.webm`));
  fs.writeFileSync(manifest,JSON.stringify({beats,pageErrors,slides:0,mainDatabaseChanged:false},null,2));
  console.log(`Completed chapter ${ch.chapter}/${script.length}: ${ch.title}`);
 }
 assert.equal(pageErrors.length,0);
}finally{await browser?.close();await client?.dispose();server.kill()}
