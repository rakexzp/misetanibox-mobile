const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('www/index.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const section=(a,b)=>script.slice(script.indexOf(a),script.indexOf(b));
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject};}
async function settle(){for(let i=0;i<12;i++)await Promise.resolve();}
function env(native=true){
 const nodes=new Map(),timeouts=new Map(),intervals=new Map(),events=new Map(),calls=[];let id=0,listener;
 const registration=deferred(),snapshots=[];
 const node=k=>{if(!nodes.has(k))nodes.set(k,{textContent:'',disabled:false,style:{},classList:{add(){},remove(){},toggle(){}},querySelectorAll:()=>[]});return nodes.get(k)};
 const ctx=vm.createContext({console,Date,Promise,Number,Error,Math,isNative:native,Vpn:native?{
  addListener(name,fn){assert.equal(name,'vpnState');listener=fn;return registration.promise},
  status(){calls.push('status');const d=deferred();snapshots.push(d);return d.promise},
  start:async()=>{calls.push('start')},stop:async()=>{calls.push('stop')}
 }:null,document:{hidden:false,getElementById:node,addEventListener:(k,f)=>events.set(k,f)},
 setTimeout:(f,ms)=>{timeouts.set(++id,{f,ms});return id},clearTimeout:k=>timeouts.delete(k),setInterval:f=>{intervals.set(++id,f);return id},clearInterval:k=>intervals.delete(k),
 setFace(){},setHomeState(){},setServersNote(){},updateHomeServer(){},renderCachedServers(){},loadProxies(){calls.push('load')},waitForServers(){calls.push('wait')},applyModeToCore(){calls.push('mode')},refreshSubscription(){calls.push('refresh')},haptic(){},dbg(){},toast(){},onboardingOpen:()=>false,getSubUrl:()=> 'https://sub',splitMode:()=> 'off',chains:()=>[],chainUsesWarp:()=>false,getHwid:()=>'',getUserAgent:()=>'',subFallbacks:()=>[],activeSub:()=>null,core:async()=>({ok:false}),localStorage:{getItem:()=>null}});
 const run=s=>vm.runInContext(s,ctx);
 run('let _mainSel=null,_providerNodes=null;'+section('let connected=false','function setStatusText'));
 run(section('function setStatusText','// состояние обложки'));
 run(section('function tunStack()', 'async function initTunStack'));
 run(section('async function toggleConnect','// ---------- серверы из API ядра'));
 run(section('function fmtBytes','// ---------- тема'));
 return {ctx,run,node,calls,registration,snapshots,events,timeouts,intervals,emit:s=>listener(s),boot:()=>run('initVpnState()')};
}
for(const running of [true,false])test('boot reconciles native running='+running+' only after listener registration',async()=>{
 const e=env();assert.equal(e.run('typeof initVpnState'),'function');const p=e.boot();
 assert.equal(e.node('connect-big').disabled,true);assert.deepEqual(e.calls,[]);
 e.registration.resolve({remove:async()=>{}});await settle();assert.deepEqual(e.calls,['status']);
 e.snapshots[0].resolve({running,state:running?'connected':'disconnected',elapsedMs:120000});await p;
 assert.equal(e.run('connected'),running);assert.equal(e.node('connect-big').disabled,false);
 assert(!e.calls.some(c=>['start','stop','wait','refresh','mode'].includes(c)));
 if(running)assert.equal(e.node('sess-time').textContent,'02:00');
});
test('tap before ready never starts or stops VPN',async()=>{const e=env();e.boot();await e.run('toggleConnect()');await e.run('toggleConnect()');assert.deepEqual(e.calls,[]);});
test('event before listener fulfillment invalidates initial snapshot generation',async()=>{
 const e=env();const p=e.boot();e.emit({state:'connected',elapsedMs:30000});e.registration.resolve({remove:async()=>{}});await settle();
 if(e.snapshots[0])e.snapshots[0].resolve({running:false,state:'disconnected',elapsedMs:0});await p;assert.equal(e.run('connected'),true);
});
test('new event wins over delayed snapshot',async()=>{const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.emit({state:'connected',elapsedMs:60000});e.snapshots[0].resolve({running:false,state:'disconnected',elapsedMs:0});await p;assert.equal(e.run('connected'),true);});
test('resume reconciles native stop and preserves session while running',async()=>{
 const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.snapshots[0].resolve({running:true,state:'connected',elapsedMs:60000});await p;const start=e.run('sessStart');
 e.ctx.document.hidden=true;e.events.get('visibilitychange')();assert.equal(e.intervals.size,0);
 e.ctx.document.hidden=false;e.events.get('visibilitychange')();await settle();e.snapshots[1].resolve({running:true,state:'connected',elapsedMs:60000});await settle();assert.equal(e.run('sessStart'),start);
 e.events.get('visibilitychange')();await settle();e.snapshots[2].resolve({running:false,state:'disconnected',elapsedMs:0});await settle();assert.equal(e.run('connected'),false);
 assert(!e.calls.some(c=>['start','stop','wait','refresh','mode'].includes(c)));
});
test('snapshot failure reports unknown, does not disconnect; retry tap only syncs',async()=>{
 const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.snapshots[0].reject(Error('offline'));await p;
 assert.match(e.node('status-val').textContent,/НЕИЗВЕСТ|НЕ УДАЛОСЬ/);await e.run('toggleConnect()');assert(!e.calls.includes('start'));assert(!e.calls.includes('stop'));
});
test('hidden connected event and late snapshot do not start UI timers or fresh effects',async()=>{
 const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.ctx.document.hidden=true;e.events.get('visibilitychange')();e.emit({state:'connected',elapsedMs:60000});e.snapshots[0].resolve({running:true,state:'connected',elapsedMs:60000});await p;
 assert.equal(e.intervals.size,0);assert(!e.calls.some(c=>['wait','refresh','mode'].includes(c)));
});
test('native connecting snapshot is not interpreted as disconnected',async()=>{const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.snapshots[0].resolve({running:false,state:'connecting',elapsedMs:0});await p;assert.equal(e.node('connect-big').disabled,true);assert.match(e.node('status-val').textContent,/ПОДКЛЮЧЕНИЕ/);await e.run('toggleConnect()');assert(!e.calls.includes('start'));});
test('web demo stays usable without native plugin',async()=>{const e=env(false);await e.boot();await e.run('toggleConnect()');assert.equal(e.run('connected'),true);});
test('bounded registration timeout remains unknown and never duplicates listener',async()=>{
 const e=env();const p=e.boot();[...e.timeouts.values()].find(t=>t.ms===5000).f();await p;
 assert.match(e.node('status-val').textContent,/НЕИЗВЕСТ/);assert.equal(e.node('connect-big').disabled,false);
 e.registration.resolve({remove:async()=>{}});await settle();await e.run('toggleConnect()');await settle();assert.deepEqual(e.calls,['status']);
});
test('foreground failure preserves last known session and never sends stop',async()=>{
 const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.snapshots[0].resolve({running:true,state:'connected',elapsedMs:90000});await p;const start=e.run('sessStart');
 e.ctx.document.hidden=true;e.events.get('visibilitychange')();e.ctx.document.hidden=false;e.events.get('visibilitychange')();await settle();e.snapshots[1].reject(Error('offline'));await settle();
 assert.equal(e.run('connected'),true);assert.equal(e.run('sessStart'),start);assert.match(e.node('status-val').textContent,/НЕИЗВЕСТ/);assert(!e.calls.includes('stop'));
});
test('foreground recovers completion event missed after a local start',async()=>{
 const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.snapshots[0].resolve({running:false,state:'disconnected',elapsedMs:0});await p;await e.run('toggleConnect()');
 e.ctx.document.hidden=true;e.events.get('visibilitychange')();e.ctx.document.hidden=false;e.events.get('visibilitychange')();await settle();e.snapshots[1].resolve({running:true,state:'connected',elapsedMs:60000});await settle();
 assert.equal(e.run('connected'),true);assert.equal(e.node('connect-big').disabled,false);assert(!e.calls.includes('wait'));
});
test('local start is single-shot and only its connected event runs fresh effects',async()=>{
 const e=env();const p=e.boot();e.registration.resolve({remove:async()=>{}});await settle();e.snapshots[0].resolve({running:false,state:'disconnected',elapsedMs:0});await p;
 await e.run('toggleConnect()');await e.run('toggleConnect()');assert.equal(e.calls.filter(c=>c==='start').length,1);
 e.emit({state:'connecting'});e.emit({state:'connected',elapsedMs:0});assert(e.calls.includes('wait'));
 e.ctx.document.hidden=true;e.events.get('visibilitychange')();for(const t of [...e.timeouts.values()])t.f();assert(!e.calls.includes('refresh'));assert(!e.calls.includes('mode'));assert.equal(e.intervals.size,0);
});
