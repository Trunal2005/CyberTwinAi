import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const repo=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const work=path.join(repo,'.cache','site-walkthrough');
const origin='http://127.0.0.1:8003';
const require=createRequire(path.join(repo,'tools/video/package.json'));
const {chromium,request,expect}=require('@playwright/test');
const script=JSON.parse(fs.readFileSync(path.join(repo,'deliverables/video/site-narration.json'),'utf8'));
const credentials=JSON.parse(fs.readFileSync(path.join(work,'credentials.json'),'utf8'));
const env={...process.env,DATABASE_URL:'sqlite:///'+path.join(work,'simulation-demo.db').replaceAll('\\','/'),
 FIREWALL_ADAPTER:'simulated',REAL_ENFORCEMENT:'false',SURICATA_EVE_PATH:'',SURICATA_LIVE_CONFIRMED:'false',CORS_ORIGINS:origin};
assert.ok(env.DATABASE_URL.includes('/.cache/site-walkthrough/'));
fs.mkdirSync(path.join(work,'raw'),{recursive:true});
const log=fs.openSync(path.join(work,'server-private.log'),'a');
const python=process.env.CYBERTWIN_PYTHON||path.join(repo,process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python');
const server=spawn(python,['-m','uvicorn','backend.main:app','--host','127.0.0.1','--port','8003','--no-access-log'],{cwd:repo,env,windowsHide:true,stdio:['ignore',log,log]});
fs.closeSync(log);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let browser,client;
const errors=[],scenes=[];
const resume=Number(process.argv.find(s=>s.startsWith('--resume='))?.split('=')[1]||1);
const manifest=path.join(work,'recording-scenes.json');
if(resume>1&&fs.existsSync(manifest))scenes.push(...JSON.parse(fs.readFileSync(manifest,'utf8')).scenes.filter(s=>s.index<resume));

async function ready(p){await expect(p.locator('h1')).toBeVisible();await p.waitForTimeout(1300);}
async function click(p,locator){await locator.scrollIntoViewIfNeeded();const box=await locator.boundingBox();if(box)await p.mouse.move(box.x+box.width*.5,box.y+box.height*.5,{steps:18});await p.waitForTimeout(250);await locator.click();await p.waitForTimeout(850);}
async function menu(p,name){await click(p,p.locator('nav').getByRole('button',{name,exact:true}));await ready(p);}
async function scroll(p,amount){await p.mouse.move(1270,610,{steps:16});await p.mouse.wheel(0,amount);await p.waitForTimeout(1400);}
async function pause(p,ms=1700){await p.waitForTimeout(ms);}

try{
 for(let i=0;i<100;i++){try{if((await fetch(origin+'/api/health')).ok)break;}catch{}if(i===99)throw Error('Isolated recording server did not start');await sleep(200);}
 client=await request.newContext({baseURL:origin});
 const login=await client.post('/api/auth/login',{data:credentials});assert.equal(login.status(),200,'Recording-only login must succeed');
 const state=await client.storageState();const status=await(await client.get('/api/status')).json();
 assert.equal(status.adapter,'simulated');assert.equal(status.enforcement_enabled,false);
 // Reset only the isolated presentation state when a recording is resumed.
 await client.post('/api/monitor',{data:{running:false,mode:'simulation'}});
 browser=await chromium.launch({headless:true});
 for(const chapter of script){
  const i=chapter.index;if(i<resume)continue;
  const ctx=await browser.newContext({storageState:i===1?undefined:state,viewport:{width:1440,height:900},
   reducedMotion:'reduce',acceptDownloads:true,recordVideo:{dir:path.join(work,'raw'),size:{width:1440,height:900}}});
  await ctx.route('**/*',r=>new URL(r.request().url()).origin===origin?r.continue():r.abort());
  const p=await ctx.newPage();p.on('pageerror',e=>errors.push({scene:i,error:e.message}));
  await p.addInitScript(()=>{document.addEventListener('DOMContentLoaded',()=>{
   const cursor=document.createElement('div');cursor.setAttribute('aria-hidden','true');cursor.style.cssText='position:fixed;width:16px;height:21px;background:white;clip-path:polygon(0 0,0 100%,32% 75%,57% 100%,75% 88%,50% 62%,94% 62%);filter:drop-shadow(1px 1px 2px black);pointer-events:none;z-index:2147483647;left:-40px;top:-40px';document.body.append(cursor);
   document.addEventListener('pointermove',e=>{cursor.style.left=e.clientX+'px';cursor.style.top=e.clientY+'px'});
   document.addEventListener('pointerdown',e=>{const ring=document.createElement('div');ring.style.cssText=`position:fixed;left:${e.clientX-16}px;top:${e.clientY-16}px;width:32px;height:32px;border:3px solid #51d8e2;border-radius:50%;pointer-events:none;z-index:2147483646`;document.body.append(ring);setTimeout(()=>ring.remove(),500)});
  })});
  const born=Date.now();await p.goto(origin+'/');await ready(p);const start=(Date.now()-born)/1000;
  await pause(p);
  if(i===1){await p.mouse.move(370,345,{steps:25});await pause(p,3500);await p.mouse.move(1070,330,{steps:25});await pause(p,3500);await scroll(p,180);await scroll(p,-180);}
  if(i===2){await scroll(p,430);await pause(p,2500);await scroll(p,430);await pause(p,2500);await scroll(p,-860);}
  if(i===3){await menu(p,'Live Monitoring');await click(p,p.getByRole('button',{name:'Start monitoring',exact:true}));await pause(p,1500);await click(p,p.getByRole('dialog').getByRole('button',{name:'Start monitoring',exact:true}));await pause(p,6500);await scroll(p,280);await click(p,p.getByRole('button',{name:'Stop monitoring',exact:true}));await click(p,p.getByRole('dialog').getByRole('button',{name:'Stop monitoring',exact:true}));await pause(p,1800);}
  if(i===4){await menu(p,'Threat Detection');await p.getByLabel('Filter severity',{exact:true}).selectOption('critical');await pause(p);await p.getByLabel('Search events',{exact:true}).fill('192.0.2.44');await pause(p);await scroll(p,300);await scroll(p,-300);await click(p,p.getByRole('button',{name:/^View event /}).first());await pause(p,2500);}
  if(i===5){await menu(p,'Threat Detection');await p.getByLabel('Filter severity',{exact:true}).selectOption('critical');await pause(p);await click(p,p.getByRole('button',{name:/^View event /}).first());await pause(p,3000);await click(p,p.getByText('Available flow features',{exact:true}));await pause(p,2000);await p.getByRole('dialog').locator('select').selectOption('investigating');await pause(p);await click(p,p.getByRole('button',{name:'Save review',exact:true}));await pause(p,1800);}
  if(i===6){await menu(p,'IP Investigation');await p.getByLabel('IP to investigate',{exact:true}).fill('192.0.2.44');await click(p,p.getByRole('button',{name:'Investigate IP',exact:true}));await expect(p.getByRole('heading',{name:'Source event history',exact:true})).toBeVisible();await pause(p,2200);await scroll(p,550);await scroll(p,520);await p.getByLabel('Evidence and context',{exact:true}).fill('Simulation demo: authentication evidence reviewed; correlate with endpoint logs.');await click(p,p.getByRole('button',{name:'Save note',exact:true}));await pause(p,2200);}
  if(i===7){await menu(p,'Settings');await pause(p,2000);await p.getByLabel('Operating mode').selectOption('manual');await click(p,p.getByRole('button',{name:'Preview policy change',exact:true}));await pause(p,2500);await click(p,p.getByRole('button',{name:'Confirm policy',exact:true}));await pause(p,1800);await scroll(p,570);await scroll(p,300);}
  if(i===8){await menu(p,'Blocklist');await click(p,p.getByRole('button',{name:'New temporary block',exact:true}));await p.getByLabel('Source IP',{exact:true}).fill('192.0.2.44');await p.getByLabel('Investigation reason',{exact:true}).fill('Isolated simulation recording: reviewed authentication failures.');await pause(p,1800);await click(p,p.getByRole('button',{name:'Preview block',exact:true}));await pause(p,3000);await click(p,p.getByRole('button',{name:'Confirm temporary block',exact:true}));await pause(p,2500);await click(p,p.getByRole('button',{name:'Remove',exact:true}).first());await pause(p,1800);await click(p,p.getByRole('button',{name:'Confirm removal',exact:true}));await pause(p,2500);}
  if(i===9){await menu(p,'Network Digital Twin');await pause(p,2000);await click(p,p.getByRole('button',{name:'Research database 10.10.3.10',exact:true}));await pause(p,3000);await click(p,p.getByRole('button',{name:'Close dialog',exact:true}));await click(p,p.getByRole('button',{name:'Devices & connections',exact:true}));await scroll(p,650);await scroll(p,500);await scroll(p,-1150);}
  if(i===10){await menu(p,'Network Digital Twin');await click(p,p.getByRole('button',{name:'Run defense comparison',exact:true}));await pause(p,1700);await scroll(p,710);await scroll(p,450);await pause(p,1700);await scroll(p,-1160);await p.getByRole('checkbox',{name:'Application server Vulnerability 6/10',exact:true}).check();await p.getByRole('checkbox',{name:'Public web server Research database Baseline allows access',exact:true}).check();await click(p,p.getByRole('button',{name:'Run defense comparison',exact:true}));await scroll(p,710);await scroll(p,400);await pause(p,3000);}
  if(i===11){await menu(p,'AI Insights');await pause(p,2200);await scroll(p,400);await pause(p,1800);await scroll(p,440);await click(p,p.getByRole('button',{name:'Predict flow',exact:true}));await pause(p,2500);await scroll(p,220);await pause(p,2000);}
  if(i===12){await menu(p,'Reports');await pause(p,2000);const dlPromise=p.waitForEvent('download');await click(p,p.getByRole('button',{name:/PDF report/}));const dl=await dlPromise;await dl.saveAs(path.join(work,'demo-export.pdf'));await pause(p,2200);await scroll(p,450);await click(p,p.getByText('Inspect report JSON',{exact:true}));await scroll(p,320);await pause(p,1800);}
  if(i===13){await scroll(p,350);await menu(p,'Overview');await pause(p,2000);await scroll(p,480);await pause(p,2500);await scroll(p,-480);await pause(p,3000);}
  const elapsed=(Date.now()-born)/1000-start;if(elapsed<12)await pause(p,(12-elapsed)*1000);
  await p.screenshot({path:path.join(work,`site-scene-${String(i).padStart(2,'0')}.png`)});await pause(p,800);
  const end=(Date.now()-born)/1000;const video=p.video();await ctx.close();await video.saveAs(path.join(work,`site-scene-${String(i).padStart(2,'0')}.webm`));
  scenes.push({index:i,title:chapter.title,start,end,duration:end-start,source:'Actual application browser video; disposable simulation database'});
  fs.writeFileSync(manifest,JSON.stringify({viewport:[1440,900],normalDataChanged:false,slidesUsed:0,scenes,pageErrors:errors},null,2));
  console.log(`Recorded actual website ${i}/${script.length}: ${chapter.title}`);
 }
 assert.equal(errors.length,0,'Website raised page errors');
}finally{await browser?.close();await client?.dispose();server.kill();}

