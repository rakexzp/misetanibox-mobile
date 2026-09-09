const fs = require('node:fs');
const path = require('node:path');

// Capacitor 6 leaves bridge null on no_webview. Keep the Android superclass
// lifecycle calls intact, guarding only the three unprotected bridge calls.
function patch(source) {
  for (const call of ['bridge.saveInstanceState(outState);', 'this.bridge.onRestart();', 'this.bridge.onDetachedFromWindow();']) {
    const guarded = 'if (bridge != null) { ' + call + ' }';
    if (source.includes(guarded)) continue;
    if (source.split(call).length !== 2) throw new Error('Unexpected Capacitor lifecycle source: ' + call);
    source = source.replace(call, guarded);
  }
  return source;
}
if (require.main === module) {
  const file = path.join(__dirname, '../node_modules/@capacitor/android/capacitor/src/main/java/com/getcapacitor/BridgeActivity.java');
  const source = fs.readFileSync(file, 'utf8');
  const updated = patch(source);
  if (updated !== source) fs.writeFileSync(file, updated);
}
module.exports = {patch};
