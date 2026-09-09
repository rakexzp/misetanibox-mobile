const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('www/index.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
function section(a,b){return script.slice(script.indexOf(a),script.indexOf(b));}
function env(){
  const nodes=new Map(), timers=new Map(); let id=0;
  function node(name){if(!nodes.has(name)){const classes=new Set(name==='view-home'?[]:['hidden']), listeners=new Map(); nodes.set(name,{id:name,style:{setProperty(k,v){this[k]=v},removeProperty(k){delete this[k]}},classList:{add(...v){v.forEach(x=>classes.add(x))},remove(...v){v.forEach(x=>classes.delete(x))},contains(x){return classes.has(x)},toggle(x,on){if(on===undefined)on=!classes.has(x);on?classes.add(x):classes.delete(x)}},addEventListener(k,f){listeners.set(k,f)},removeEventListener(k){listeners.delete(k)},listeners,offsetWidth:400});}return nodes.get(name)}
  const store=new Map(); const ctx=vm.createContext({console,Map,Date,JSON,Promise,Error,crypto:require('node:crypto').webcrypto,localStorage:{getItem:k=>store.get(k)||null,setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k)},window:{innerWidth:400,matchMedia:()=>({matches:false})},document:{getElementById:node,querySelector:()=>node('app'),querySelectorAll:()=>[...nodes.values()].filter(n=>n.id.startsWith('view-'))},setTimeout:f=>{timers.set(++id,f);return id},clearTimeout:i=>timers.delete(i),requestAnimationFrame:f=>{timers.set(++id,f);return id},cancelAnimationFrame:i=>timers.delete(i),navigator:{},Vpn:{},applyModeLabel(){},applyExpertUi(){},renderSubs(){},toast(){},renderServerSheet(){},updateCoverMeta(){},scheduleReminder(){},parseSubNames:()=>[],parseUserinfo:()=>({}),getPreferred:()=>store.get('mise_preferred'),getHwid:()=> 'hwid',subFallbacks:s=>s.fallbacks||[],safeJson:s=>{try{return JSON.parse(s)}catch{return null}},getUserAgent:s=>s.ua||'default',connected:false});
  return {ctx,node,store,run:s=>vm.runInContext(s,ctx),flush(){for(let i=0;timers.size&&i<10;i++){const all=[...timers.values()];timers.clear();all.forEach(f=>f())}},timers};
}
test('inline JavaScript parses',()=>new vm.Script(script));
test('panel RAF and close cleanup cannot resurrect an old panel',()=>{
 const e=env();e.run("let tab='home';"+section('// Один владелец перехода','// ---------- свайп-навигация'));
 e.run("openPanel('rules',true);closePanel('rules',false);openPanel('subs',true)");e.flush();
 assert(e.node('view-rules').classList.contains('hidden'));assert(!e.node('view-subs').classList.contains('hidden'));
 e.run("closePanel('subs',true)");e.flush();assert(e.node('drawer-dim').classList.contains('hidden'));assert.equal(e.node('view-home').style.transform,'');assert.equal(e.timers.size,0);
});
test('transition replacement removes old listeners and only runs current completion',()=>{
 const e=env();e.run(section('// Один владелец перехода','function settleViews'));
 e.run("var count=0;transEnd(document.getElementById('a'),()=>count+=10);transEnd(document.getElementById('b'),()=>count++)");
 assert.equal(e.node('a').listeners.size,0);e.flush();assert.equal(e.run('count'),1);assert.equal(e.node('b').listeners.size,0);
});
function refreshEnv(){const e=env();e.run(section('function subs(){','function switchSub')+section('const subRequests=','async function reconnect'));
 e.run("saveSubs([{id:'a',url:'https://a',ua:'custom',fallbacks:['https://b']}]);setActiveSub('a');var calls=0,saves=0;Vpn.saveSubCache=async()=>{saves++};Vpn.fetchSub=opts=>{calls++;globalThis.opts=opts;return new Promise(r=>globalThis.resolveFetch=r)}");return e;}
const good={status:200,body:'proxies: []',format:'mihomo',names:['keep'],title:'fresh',sheet:'{"members":["keep"]}'};
test('refresh coalesces double tap, preserves selection and sends UA/HWID/fallbacks',async()=>{
 const e=refreshEnv();e.store.set('mise_preferred','keep');const p=e.run('refreshSubscription(true)');const q=e.run('refreshSubscription(true)');assert.equal(e.run('calls'),1);assert.equal(e.run('opts.userAgent'),'custom');assert.equal(e.run('opts.hwid'),'hwid');e.ctx.resolveFetch(good);assert.equal(await p,true);await q;assert.equal(e.run('saves'),1);assert.equal(e.store.get('mise_preferred'),'keep');assert.equal(e.run('activeSub().title'),'fresh');
});
for(const change of ["setActiveSub('b')","saveSubs([]);++subGeneration","setUserAgentPlaceholder=1;subsChanged=subs();subsChanged[0].ua='new';saveSubs(subsChanged)"]){test('stale response rejected: '+change,async()=>{const e=refreshEnv();const p=e.run('refreshSubscription(true)');e.run(change);e.ctx.resolveFetch(good);assert.equal(await p,false);assert.equal(e.run('saves'),0);});}
for(const response of [{status:200,body:'<html>bad</html>'},{status:0,error:'timeout'},{...good,cached:true}])test('manual failure retains cache: '+JSON.stringify(response),async()=>{const e=refreshEnv();e.store.set('mise_mainServers:a','old');const p=e.run('refreshSubscription(true)');e.ctx.resolveFetch(response);assert.equal(await p,false);assert.equal(e.store.get('mise_mainServers:a'),'old');assert.equal(e.run('saves'),0);});
test('settings/back rapid reversal and canceled panel gesture settle cleanly',()=>{
 const e=env(), events=new Map();e.ctx.document.addEventListener=(k,f)=>events.set(k,f);e.ctx.onboardingOpen=()=>false;e.ctx.prepView=()=>{};
 e.run(section("let tab='home'",'// лист серверов: тянется вниз'));e.ctx.subs=()=>[];e.ctx.activeSub=()=>null;
 e.node('view-home');e.node('view-settings');e.node('view-rules');e.node('view-subs');
 const views=e.ctx.document.querySelectorAll;e.ctx.document.querySelectorAll=s=>s==='.view'?views():[];
 e.run("go('settings');navBack();go('settings');navBack()");e.flush();assert.equal(e.run('tab'),'home');assert(e.node('view-settings').classList.contains('hidden'));
 e.ctx.document.querySelectorAll=()=>[];
 events.get('touchstart')({touches:[{clientX:350,clientY:100}]});events.get('touchmove')({touches:[{clientX:40,clientY:100}]});events.get('touchcancel')();e.flush();assert.equal(e.run('tab'),'home');assert(e.node('view-rules').classList.contains('hidden'));
 e.run("openPanel('subs',true)");e.ctx.document.hidden=true;events.get('visibilitychange')();e.flush();assert.equal(e.run('panelOpen'),'subs');
});
test('connected refresh applies validated cache through reconnect',async()=>{const e=refreshEnv();e.run('connected=true;var applied=false;async function reconnect(cache){applied=cache}');const p=e.run('refreshSubscription(true)');e.ctx.resolveFetch(good);assert.equal(await p,true);assert.equal(e.run('applied'),true);});
test('native validation and API guards remain in place',()=>{
 const root='android/app/src/main/java/network/geodema/misetanibox/';const plugin=fs.readFileSync(root+'VpnPlugin.kt','utf8'),sub=fs.readFileSync(root+'Subscription.kt','utf8');
 assert.match(plugin,/SDK_INT >= 33\) \{\s*val attrs = android.os.VibrationAttributes/);
 assert.match(sub,/convert\(body\)[\s\S]*temp.writeText\(body\)/);assert.match(sub,/validated\(fetch\(u,/);assert.match(plugin,/fun saveSubCache/);
 assert.match(script,/touchcancel', cancelGesture/);assert.match(script,/if\(onboardingOpen\(\)\)\{ document.activeElement/);assert.match(script,/allowCache:false/);
});
