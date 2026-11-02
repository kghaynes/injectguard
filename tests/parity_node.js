// Usage: node tests/parity_node.js cases.json  -> prints JSON results using the extension's detector
const fs = require('fs'), path = require('path');
globalThis.self = globalThis;
const ext = path.join(__dirname, '..', 'extension');
eval(fs.readFileSync(path.join(ext, 'rules.js'), 'utf8'));
eval(fs.readFileSync(path.join(ext, 'detector.js'), 'utf8'));
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
console.log(JSON.stringify(cases.map(c => { const r = self.InjectGuard.scan('t', 'page', c);
  return { verdict: r.verdict, score: r.score, ids: r.findings.map(f => f.rule_id + ':' + f.score).sort() }; })));
