const $ = s => document.querySelector(s);
const DEFAULTS = { autoScan: true, showBanner: true, bannerMin: 'malicious', notify: true, notifyMin: 'malicious',
  useEngine: true, enginePort: 47321, engineToken: '' };
const CHECKS = ['autoScan', 'useEngine', 'showBanner', 'notify'];
const VALUES = ['bannerMin', 'notifyMin', 'engineToken', 'enginePort'];

async function load() {
  const { settings = {}, trustedSites = [], history = [] } = await chrome.storage.local.get(['settings', 'trustedSites', 'history']);
  const s = { ...DEFAULTS, ...settings };
  CHECKS.forEach(k => $('#' + k).checked = !!s[k]);
  VALUES.forEach(k => $('#' + k).value = s[k]);
  $('#trusted').value = trustedSites.join('\n');
  $('#histCount').textContent = `${history.length} alert(s) stored`;
}

async function save() {
  const { settings = {} } = await chrome.storage.local.get('settings');
  const s = { ...DEFAULTS, ...settings };
  CHECKS.forEach(k => s[k] = $('#' + k).checked);
  VALUES.forEach(k => s[k] = $('#' + k).value.trim());
  s.enginePort = parseInt(s.enginePort, 10) || 47321;
  const trustedSites = [...new Set($('#trusted').value.split(/\s+/).map(x => x.trim().toLowerCase()).filter(Boolean))];
  await chrome.storage.local.set({ settings: s, trustedSites });
  $('#saved').textContent = 'Saved.';
  setTimeout(() => $('#saved').textContent = '', 2500);
}

$('#save').onclick = save;
$('#test').onclick = async () => {
  await save();
  $('#testMsg').textContent = 'Testing…';
  const st = await chrome.runtime.sendMessage({ type: 'engineStatus' });
  $('#testMsg').textContent = st.msg;
  $('#testMsg').style.color = st.ok ? 'var(--green)' : 'var(--orange)';
};
$('#exportHist').onclick = async () => {
  const { history = [] } = await chrome.storage.local.get('history');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' }));
  a.download = 'injectguard-alerts.json';
  a.click();
};
$('#clearHist').onclick = async () => { await chrome.storage.local.set({ history: [] }); load(); };
load();
