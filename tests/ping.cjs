const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('www/index.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const section=(a,b)=>script.slice(script.indexOf(a),script.indexOf(b));
function env({connected=false,nodes={},proxies=null,tcp,delay}={}){
 const log={toasts:[],tcp:[],delay:[],sheet:0,proxies:0,max:0};let live=0;
 const track=async fn=>{live++;log.max=Math.max(log.max,live);await new Promise(r=>setImmediate(r));try{return fn()}finally{live--}};
 const ctx=vm.createContext({Promise,Array,Object,Set,String,parseInt,encodeURIComponent,setTimeout,clearTimeout,
  connected,_proxies:proxies,delays:{},toast:m=>log.toasts.push(m),subFlags:()=>({}),activeSub:()=>({nodes}),
  isGroup:p=>Array.isArray(p&&p.all),renderProxies:()=>log.proxies++,renderServerSheet:()=>log.sheet++,
  Vpn:{tcpPing:a=>track(()=>{log.tcp.push(a);return {ms:tcp(a)}})},
  core:(m,url)=>track(()=>{const n=decodeURIComponent(url.split('/')[2].split('?')[0]);log.delay.push(url);return {ok:true,data:{delay:delay(n)}}})});
 vm.runInContext(section('const PING_POOL','\n// ---------- подписка'),ctx);
 return {ctx,log,ping:()=>vm.runInContext('pingAll()',ctx),delays:()=>vm.runInContext('delays',ctx)};
}
test('offline without nodes tells the user instead of doing nothing',async()=>{
 const e=env();await e.ping();assert.deepEqual(e.log.toasts,['Подключитесь, чтобы проверить серверы']);
});
test('offline pings nodes over TCP, parses host:port and retries failures once',async()=>{
 const seen={};const e=env({nodes:{A:'a.example:8443',B:'[2001:db8::1]:443',C:'c.example:443'},tcp:({host})=>{seen[host]=(seen[host]||0)+1;return host==='c.example'?(seen[host]>1?77:-1):10}});
 await e.ping();
 assert.equal(JSON.stringify(e.delays()),JSON.stringify({A:10,B:10,C:77}));
 assert.equal(JSON.stringify(e.log.tcp.slice(0,2)),JSON.stringify([{host:'a.example',port:8443},{host:'2001:db8::1',port:443}]));
 assert.equal(seen['c.example'],2);assert(e.log.sheet>0);
});
test('connected runs at most PING_POOL URL tests at once with a 5s timeout and redraws the sheet',async()=>{
 const proxies={DIRECT:{}};for(let i=0;i<30;i++)proxies['n'+i]={};proxies.G={all:['n1']};
 const e=env({connected:true,proxies,delay:()=>50});await e.ping();
 assert.equal(e.log.delay.length,30);assert(e.log.max<=8&&e.log.max>1,'max '+e.log.max);
 assert(e.log.delay.every(u=>u.includes('timeout=5000')));assert(e.log.sheet>0&&e.log.proxies>0);
});
