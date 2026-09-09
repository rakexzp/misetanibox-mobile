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
function multiRefreshEnv(){
 const e=refreshEnv();e.run("saveSubs([...subs(),{id:'b',name:'B',url:'https://other',ua:'other-UA'}]);connected=true;var stops=0,homeUpdates=0;Vpn.stop=async()=>{stops++};renderServerSheet=updateCoverMeta=()=>{homeUpdates++}");
 e.run(section('async function reconnect(', 'function delSub('));
 e.run("var pending=new Map(),saved=[];Vpn.fetchSub=opts=>{calls++;return new Promise(r=>pending.set(opts.url,{opts,resolve:r}))};Vpn.saveSubCache=async opts=>{saved.push(opts);saves++}");
 e.store.set('mise_preferred','active-choice');e.store.set('mise_subFormat','active-format');e.store.set('mise_mainServers:a','active-main');e.store.set('mise_lastServers:a','active-last');e.store.set('mise_subErr:a','active-error');
 e.run(section('function renderSubs(){','// ---------- режим маршрутизации'));
 Object.assign(e.ctx,{esc:String,q:String,fmtBytes:String,subExpiryText:()=>'',uaLabel:String});
 return e;
}
function refreshButtons(e){e.run('renderSubs()');return [...e.node('subs-list').innerHTML.matchAll(/<button\b[^>]*class="sub-refresh[^>]*>/g)].map(m=>m[0]);}
test('inactive refresh isolates cache, selection, metadata and connected VPN',async()=>{
 const e=multiRefreshEnv(),before=new Map(e.store),p=e.run("refreshSubscription(true,false,'b')");
 const request=e.run("pending.get('https://other')");assert.ok(request);assert.equal(request.opts.userAgent,'other-UA');
 request.resolve({...good,names:['other'],sheet:'{"members":["other"]}'});assert.equal(await p,true);
 for(const key of ['mise_subActive','mise_subUrl','mise_preferred','mise_subFormat','mise_mainServers:a','mise_lastServers:a','mise_subErr:a'])assert.equal(e.store.get(key),before.get(key),key);
 assert.equal(e.run('stops'),0);assert.equal(e.run('homeUpdates'),0);assert.equal(e.run('connected'),true);
 assert.equal(e.run('activeSub().title'),undefined);assert.equal(e.run("subs().find(s=>s.id==='b').title"),'fresh');
 assert.deepEqual(JSON.parse(e.store.get('mise_mainServers:b')).all,['other']);assert.equal(JSON.parse(e.store.get('mise_mainServers:b')).now,null);
 assert.equal(e.run('saved[0].url'),'https://other');
});
test('each row refresh stops propagation and has independent busy state',async()=>{
 const e=multiRefreshEnv();let buttons=refreshButtons(e);assert.equal(buttons.length,2);
 let stopped=0;e.ctx.event={stopPropagation(){stopped++}};
 const p=e.run(buttons[1].match(/onclick="([^"]*)"/)[1]);assert.equal(stopped,1);assert.equal(e.run('activeSubId()'),'a');
 buttons=refreshButtons(e);assert.doesNotMatch(buttons[0],/disabled/);assert.match(buttons[1],/disabled/);
 const q=e.run("refreshSubscription(true,false,'a')"),duplicate=e.run("refreshSubscription(true,false,'b')");assert.equal(e.run('calls'),2);
 assert.ok(refreshButtons(e).every(b=>b.includes('disabled')));
 e.run("pending.get('https://other')").resolve(good);
 // Finish the inactive request first; the active row must remain busy.
 await p;await duplicate;buttons=refreshButtons(e);assert.match(buttons[0],/disabled/);assert.doesNotMatch(buttons[1],/disabled/);
 e.run("pending.get('https://a').resolve({status:0,error:'offline'})");await q;assert.ok(refreshButtons(e).every(b=>!b.includes('disabled')));
});
for(const change of ["saveSubs(subs().filter(s=>s.id!=='b'));++subGeneration","const changed=subs();changed[1].ua='changed';saveSubs(changed)","setActiveSub('b')"]){
 test('inactive stale response cannot apply after '+change,async()=>{
  const e=multiRefreshEnv(),p=e.run("refreshSubscription(true,false,'b')"),request=e.run("pending.get('https://other')");assert.ok(request);
  e.run(change);request.resolve(good);assert.equal(await p,false);assert.equal(e.run('saves'),0);assert.equal(e.run('stops'),0);assert.equal(e.store.has('mise_mainServers:b'),false);
 });
}
test('inactive refresh failure writes only its own error and retains caches',async()=>{
 const e=multiRefreshEnv();e.store.set('mise_mainServers:b','old-b');const p=e.run("refreshSubscription(true,false,'b')");const request=e.run("pending.get('https://other')");assert.ok(request);
 request.resolve({status:0,error:'offline'});assert.equal(await p,false);assert.equal(e.store.get('mise_subErr:b'),'offline');assert.equal(e.store.get('mise_subErr:a'),'active-error');assert.equal(e.store.get('mise_mainServers:b'),'old-b');assert.equal(e.run('stops'),0);
});
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
function navigationEnv(reduced=false){
 const e=env(),events=new Map();e.ctx.document.addEventListener=(k,f)=>events.set(k,f);e.ctx.onboardingOpen=()=>false;e.ctx.window.matchMedia=()=>({matches:reduced});
 e.run(section("let tab='home'",'// лист серверов: тянется вниз'));Object.assign(e.ctx,{subs:()=>[],activeSub:()=>null,renderChains(){},openAppsScreen(){}});
 for(const n of ['home','settings','chains','apps','rules','subs'])e.node('view-'+n);
 const views=e.ctx.document.querySelectorAll;e.ctx.document.querySelectorAll=s=>s==='.view'?views():[];
 e.events=events;return e;
}
function assertNavigationClean(e,tab){
 assert.equal(e.run('tab'),tab);assert.equal(e.timers.size,0);
 for(const n of ['home','settings','chains','apps']){
  const v=e.node('view-'+n);assert.equal(v.classList.contains('hidden'),n!==tab,n);
  for(const c of ['push-in','push-out','pop-in','pop-out','drag-under','drag-over','anim'])assert.equal(v.classList.contains(c),false,n+' '+c);
  for(const p of ['transform','opacity','transition'])assert.ok(!v.style[p],n+' '+p);
  assert.equal(v.style['--dim'],undefined);assert.equal(v.listeners.size,0);
 }
}
test('pseudo-element animation cannot finish the page transition',()=>{
 const e=navigationEnv();e.run("go('settings')");const to=e.node('view-settings');
 to.listeners.get('animationend')({target:to,pseudoElement:'::after'});
 assert.equal(e.node('view-home').classList.contains('hidden'),false);
 to.listeners.get('animationend')({target:to,pseudoElement:''});assertNavigationClean(e,'settings');
});
test('edge-back takes ownership from an unfinished settings push',()=>{
 const e=navigationEnv();e.run("go('settings')");
 e.events.get('touchstart')({touches:[{clientX:5,clientY:100}]});e.events.get('touchmove')({touches:[{clientX:100,clientY:100}]});
 e.flush();assert.equal(e.node('view-home').classList.contains('hidden'),false);assert.equal(e.node('view-settings').listeners.size,0);
 e.events.get('touchcancel')();assertNavigationClean(e,'settings');
});
for(const reduced of [false,true])test(`settings push/back cleanup and nested return (reduced motion: ${reduced})`,()=>{
 const e=navigationEnv(reduced);e.run("go('settings')");e.flush();assertNavigationClean(e,'settings');
 assert.equal(e.node('view-home').classList.contains('nav-visited'),true);
 e.run("go('chains')");e.flush();e.run("go('settings')");assert.equal(e.node('view-chains').classList.contains('pop-out'),true);e.flush();assertNavigationClean(e,'settings');
 assert.equal(e.run('JSON.stringify(navStack)'), '["settings"]');
 e.run("navBack();go('settings');navBack()");e.flush();assertNavigationClean(e,'home');assert.equal(e.run('navBack()'),'exit');
});
test('moving screens and side panels have no decorative edge shadows',()=>{
 const css=html.match(/<style>([\s\S]*?)<\/style>/)[1].replace(/\/\*[\s\S]*?\*\//g,'');
 const rules=[...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].filter(([,selector])=>selector.split(',').some(s=>/^(?:#view-(?:rules|subs)|\.view\.(?:drag-over|drag-under|push-in|push-out|pop-in|pop-out))(?=[:.\s>]|$)/.test(s.trim())));
 assert.ok(rules.length>0);
 for(const [,selector,body] of rules){
  assert.doesNotMatch(body,/(?:box-shadow|text-shadow)\s*:\s*(?!none\b)[^;]+|drop-shadow\(/,selector);
  assert.doesNotMatch(body,/linear-gradient\(\s*(?:to (?:left|right)|90deg|270deg)/,selector);
 }
});
for(const name of ['rules','subs'])for(const reduced of [false,true])test(`${name} close and canceled swipe leave no dim (reduced motion: ${reduced})`,()=>{
 const e=env(),events=new Map();e.ctx.window.matchMedia=()=>({matches:reduced});e.ctx.document.addEventListener=(k,f)=>events.set(k,f);e.ctx.onboardingOpen=()=>false;e.ctx.prepView=()=>{};
 e.run(section("let tab='home'",'// лист серверов: тянется вниз'));e.ctx.subs=()=>[];e.ctx.activeSub=()=>null;e.ctx.document.querySelectorAll=()=>[];
 const clean=()=>{assert.equal(e.run('tab'),'home');assert.equal(e.run('panelOpen'),'');assert.equal(e.node('drawer-dim').style.opacity,'0');assert(e.node('drawer-dim').classList.contains('hidden'));assert(!e.node('drawer-dim').classList.contains('opening'));assert(!e.node('drawer-dim').classList.contains('anim'));assert.equal(e.node('view-home').style.transform,'');for(const n of ['rules','subs'])assert(e.node('view-'+n).classList.contains('hidden'));assert.equal(e.timers.size,0);};
 e.run(`openPanel('${name}',true)`);e.flush();assert.equal(e.node('drawer-dim').style.opacity,'0.500');e.run(`closePanel('${name}',true)`);assert.equal(Number(e.node('drawer-dim').style.opacity),0);e.flush();clean();
 const start=name==='rules'?350:40,end=name==='rules'?40:350;
 events.get('touchstart')({touches:[{clientX:start,clientY:100}]});events.get('touchmove')({touches:[{clientX:end,clientY:100}]});assert(Number(e.node('drawer-dim').style.opacity)>0);events.get('touchcancel')();e.flush();clean();
});
test('subscription refresh renders canonical Lucide refresh-cw with a 44px target',()=>{
 const e=multiRefreshEnv();refreshButtons(e);
 const svg=e.node('subs-list').innerHTML.match(/class="sub-refresh[^>]*>(<svg[\s\S]*?<\/svg>)/)[1];
 assert.deepEqual([...svg.matchAll(/<path d="([^"]+)"/g)].map(m=>m[1]),['M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8','M21 3v5h-5','M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16','M8 16H3v5']);
 assert.match(svg,/stroke-width="2"/);assert.match(svg,/aria-hidden="true"/);
 const css=html.match(/\.sub-refresh\{([^}]+)\}/)[1];assert.match(css,/width:44px/);assert.match(css,/height:44px/);
});
test('connected refresh applies validated cache through reconnect',async()=>{const e=refreshEnv();e.run('connected=true;var applied=false;async function reconnect(cache){applied=cache}');const p=e.run('refreshSubscription(true)');e.ctx.resolveFetch(good);assert.equal(await p,true);assert.equal(e.run('applied'),true);});
test('native validation and API guards remain in place',()=>{
 const root='android/app/src/main/java/network/geodema/misetanibox/';const plugin=fs.readFileSync(root+'VpnPlugin.kt','utf8'),sub=fs.readFileSync(root+'Subscription.kt','utf8');
 assert.match(plugin,/SDK_INT >= 33\) \{\s*val attrs = android.os.VibrationAttributes/);
 assert.match(sub,/convert\(body\)[\s\S]*temp.writeText\(body\)/);assert.match(sub,/validated\(fetch\(u,/);assert.match(plugin,/fun saveSubCache/);
 assert.match(script,/touchcancel', cancelGesture/);assert.match(script,/if\(onboardingOpen\(\)\)\{ document.activeElement/);assert.match(script,/allowCache:false/);
});
