const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const root='android/app/src/main/java/network/geodema/misetanibox/';
// Execute the API dispatch branches, replacing only Android's platform calls.
function runBranch(source, start, end, api, extra={}) {
 const body=source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start)));
 const code=body.replaceAll('Build.VERSION.SDK_INT','api').replaceAll('Build.VERSION_CODES.O','26').replaceAll('Build.VERSION_CODES.M','23').replace('context.startForegroundService(i) else','context.startForegroundService(i); else');
 return vm.runInNewContext(code,{api,...extra});
}
test('legacy haptic returns before touching VibrationEffect',()=>{
 const source=fs.readFileSync(root+'VpnPlugin.kt','utf8');
 for(const api of [22,25,26,29,30,33]){
  const calls=[];
  const start=source.indexOf('if (Build.VERSION.SDK_INT < 26)');
  assert.ok(start>0,'missing pre-26 haptic branch');
  const body=source.slice(start,source.indexOf('val effect',start)).replace(/@Suppress\("DEPRECATION"\)\s*/g,'').replace('if (kind == "heavy") 30L else 10L','kind == "heavy" ? 30 : 10');
  vm.runInNewContext('(function(){'+body.replaceAll('Build.VERSION.SDK_INT','api')+'})()',{api,kind:'heavy',vib:{vibrate:n=>calls.push(n)},call:{resolve:()=>calls.push('resolved')}});
  assert.deepEqual(calls,api<26?[30,'resolved']:[]);
 }
});
test('VPN launch dispatch supports API 22 through 35',()=>{
 const source=fs.readFileSync(root+'VpnPlugin.kt','utf8');
 for(const api of [22,23,25,26,30,33,35]){
  const calls=[];
  runBranch(source,'if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)', '\n    }',api,{context:{startForegroundService:()=>calls.push('foreground'),startService:()=>calls.push('legacy')},i:{}});
  assert.deepEqual(calls,[api>=26?'foreground':'legacy']);
 }
});
test('expiry scheduling supports API 22 without idle API',()=>{
 const source=fs.readFileSync(root+'ExpiryReminder.kt','utf8');
 for(const api of [22,23,35]){
  const calls=[];
  runBranch(source,'if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)', '\n        }',api,{am:{setAndAllowWhileIdle:()=>calls.push('idle'),set:()=>calls.push('legacy')},AlarmManager:{RTC_WAKEUP:0},c:{timeInMillis:10},pending:()=>({}),ctx:{},d:1});
  assert.deepEqual(calls,[api>=23?'idle':'legacy']);
 }
});
test('Capacitor null bridge lifecycle patch is applied and idempotent',()=>{
 const patch=require('../scripts/patch-capacitor.cjs');
 const path='node_modules/@capacitor/android/capacitor/src/main/java/com/getcapacitor/BridgeActivity.java';
 const original=fs.readFileSync(path,'utf8');
 const updated=patch.patch(original);
 assert.equal(patch.patch(updated),updated);
 for(const call of ['bridge.saveInstanceState(outState);','this.bridge.onRestart();','this.bridge.onDetachedFromWindow();']){
  const guarded='if (bridge != null) { '+call+' }';
  assert.ok(updated.includes(guarded));
  assert.equal(vm.runInNewContext(guarded.replaceAll('this.bridge','bridge'),{bridge:null}),undefined);
 }
});
