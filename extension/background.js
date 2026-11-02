// InjectGuard service worker: per-tab state, badge, context menus, notifications, and the link to the desktop engine.
importScripts('rules.js', 'detector.js');

const DEFAULTS = {
  autoScan: true, showBanner: true, bannerMin: 'malicious', notify: true, notifyMin: 'malicious',
  useEngine: true, enginePort: 47321, engineToken: '', showInfo: false
};
const tabs = new Map();          // tabId -> {url, title, frames: {frameId: result}, final}
const ORDER = { clean: 0, skipped: 0, error: 0, suspicious: 1, malicious: 2 };

async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULTS, ...(settings || {}) };
}

// ------------------------------------------------------------------ desktop engine
async function engine(path, body, settings) {
  const s = settings || await getSettings();
  if (!s.useEngine || !s.engineToken) return null;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), path === '/scan/url' ? 60000 : 20000);
  try {
    const r = await fetch(`http://127.0.0.1:${s.enginePort}${path}`, {
      method: body ? 'POST' : 'GET', signal: ctl.signal,
      headers: { 'Content-Type': 'application/json', 'X-InjectGuard-Token': s.engineToken },
      body: body ? JSON.stringify(body) : undefined
    });
    if (!r.ok) throw new Error(`engine ${r.status}`);
    return await r.json();
  } catch (e) {
    return { __error: String(e.message || e) };
  } finally { clearTimeout(t); }
}

async function engineStatus() {
  const s = await getSettings();
  try {
    const h = await fetch(`http://127.0.0.1:${s.enginePort}/health`).then(r => r.json());
    if (!s.engineToken) return { ok: false, reachable: true, msg: `Engine ${h.version} found — paste the pairing token in Options.` };
    const st = await engine('/status', null, s);
    if (st && !st.__error) return { ok: true, reachable: true, msg: `Paired with engine ${st.version}`, status: st };
    return { ok: false, reachable: true, msg: 'Engine found but token rejected — re-copy it (Tools → Copy Extension Pairing Token).' };
  } catch (e) {
    return { ok: false, reachable: false, msg: 'Desktop engine not running — using in-browser checks only.' };
  }
}

// ------------------------------------------------------------------ results
function merge(tabId) {
  const t = tabs.get(tabId);
  if (!t) return null;
  const frames = Object.values(t.frames);
  if (!frames.length) return null;
  const top = t.frames[0] || frames[0];
  const findings = frames.flatMap((r, i) => r.findings.map(f => ({ ...f, frame: r.frame || (i ? 'frame' : 'top') })));
  findings.sort((a, b) => b.score - a.score);
  const [score, verdict] = self.InjectGuard.overall(findings);
  return {
    ...top, findings, score, verdict, frames: frames.length,
    engine: frames.every(r => r.engine === 'desktop') ? 'desktop' : frames.some(r => r.engine === 'desktop') ? 'mixed' : 'browser'
  };
}

async function setBadge(tabId, res) {
  if (!res) { chrome.action.setBadgeText({ tabId, text: '' }); return; }
  const color = { malicious: '#c62828', suspicious: '#ef6c00', clean: '#2e7d32' }[res.verdict] || '#757575';
  const text = res.verdict === 'clean' ? '' : res.verdict === 'malicious' ? '!' : String(res.score);
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setTitle({ tabId, title: `InjectGuard — ${res.verdict.toUpperCase()} (score ${res.score})` });
}

async function remember(res, tab) {
  if (ORDER[res.verdict] < 1) return;
  const { history = [] } = await chrome.storage.local.get('history');
  const key = res.target + '|' + res.verdict;
  const filtered = history.filter(h => h.key !== key);
  filtered.unshift({
    key, url: res.target, title: (tab && tab.title) || '', verdict: res.verdict, score: res.score, at: Date.now(),
    top: res.findings.slice(0, 3).map(f => ({ title: f.title, score: f.score, hidden_reason: f.hidden_reason }))
  });
  await chrome.storage.local.set({ history: filtered.slice(0, 300) });
}

const notified = new Set();
async function maybeNotify(res, tabId, s) {
  if (!s.notify || ORDER[res.verdict] < ORDER[s.notifyMin]) return;
  const k = tabId + '|' + res.target;
  if (notified.has(k)) return;
  notified.add(k);
  chrome.notifications.create('ig-' + tabId + '-' + Date.now(), {
    type: 'basic', iconUrl: 'icons/icon128.png', priority: 2,
    title: `InjectGuard: ${res.verdict.toUpperCase()} page (score ${res.score})`,
    message: `${new URL(res.target).hostname} hides text aimed at AI tools: ${res.findings[0]?.title || ''}`
  });
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg.type === 'pageResult' && sender.tab) {
      const tabId = sender.tab.id, frameId = sender.frameId || 0;
      const s = await getSettings();
      let t = tabs.get(tabId);
      if (!t || (frameId === 0 && t.url !== msg.url)) { t = { url: msg.url, title: msg.title, frames: {} }; tabs.set(tabId, t); }
      let res = msg.result;
      // Second opinion from the desktop engine (full rules + optional local AI + shared history)
      const er = await engine('/scan/page', { url: msg.url, title: msg.title, segments: msg.segments, record: ORDER[res.verdict] >= 1 }, s);
      if (er && !er.__error) res = { ...er, engine: 'desktop', frame: res.frame };
      else if (er && er.__error) res.errors = [...(res.errors || []), 'Desktop engine: ' + er.__error];
      t.frames[frameId] = res;
      const merged = merge(tabId);
      await setBadge(tabId, merged);
      chrome.tabs.sendMessage(tabId, { type: 'finalResult', result: merged }, { frameId: 0 }).catch(() => { });
      await remember(merged, sender.tab);
      await maybeNotify(merged, tabId, s);
      reply({ ok: true });
      return;
    }
    if (msg.type === 'getTabResult') { reply(merge(msg.tabId)); return; }
    if (msg.type === 'engineStatus') { reply(await engineStatus()); return; }
    if (msg.type === 'scanUrl') { reply(await scanUrl(msg.url)); return; }
    if (msg.type === 'scanText') {
      const s = await getSettings();
      const er = await engine('/scan/text', { text: msg.text, label: 'Selected text' }, s);
      reply(er && !er.__error ? { ...er, engine: 'desktop' } : self.InjectGuard.scan('Selected text', 'text',
        [{ text: msg.text, location: 'selection', visibility: 'visible' }]));
      return;
    }
    reply(null);
  })();
  return true;
});

async function scanUrl(url) {
  const er = await engine('/scan/url', { url });
  if (!er) return { verdict: 'error', target: url, score: 0, findings: [], errors: ['Pair the desktop engine to scan linked files (PDF, Office).'] };
  if (er.__error) return { verdict: 'error', target: url, score: 0, findings: [], errors: [er.__error] };
  return { ...er, engine: 'desktop' };
}

chrome.tabs.onRemoved.addListener(id => tabs.delete(id));
chrome.tabs.onUpdated.addListener((id, info) => {
  if (info.status === 'loading' && info.url) { tabs.delete(id); chrome.action.setBadgeText({ tabId: id, text: '' }); }
});

// ------------------------------------------------------------------ context menus
const MENUS = [
  ['ig-scan-page', 'Scan this page for hidden AI instructions', ['page', 'frame']],
  ['ig-highlight', 'Reveal hidden text on this page', ['page', 'frame']],
  ['ig-scan-selection', 'Scan selected text with InjectGuard', ['selection']],
  ['ig-scan-link', 'Scan linked page or file (PDF, Office) with InjectGuard', ['link']],
  ['ig-trust', 'Always trust this site (skip auto-scan)', ['page']]
];
chrome.runtime.onInstalled.addListener(async (d) => {
  chrome.contextMenus.removeAll(() => {
    for (const [id, title, contexts] of MENUS) chrome.contextMenus.create({ id, title, contexts });
  });
  const { settings } = await chrome.storage.local.get('settings');
  if (!settings) await chrome.storage.local.set({ settings: DEFAULTS });
  if (d.reason === 'install') chrome.runtime.openOptionsPage();
});

async function showResultTab(res) {
  await chrome.storage.session.set({ lastAdHoc: res });
  chrome.tabs.create({ url: chrome.runtime.getURL('popup.html?view=adhoc') });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'ig-scan-page') chrome.tabs.sendMessage(tab.id, { type: 'scan' }).catch(() => { });
  if (info.menuItemId === 'ig-highlight') chrome.tabs.sendMessage(tab.id, { type: 'highlight', on: true }).catch(() => { });
  if (info.menuItemId === 'ig-scan-selection') {
    const s = await getSettings();
    const er = await engine('/scan/text', { text: info.selectionText, label: 'Selected text' }, s);
    const res = er && !er.__error ? { ...er, engine: 'desktop' } :
      self.InjectGuard.scan('Selected text', 'text', [{ text: info.selectionText, location: 'selection', visibility: 'visible' }]);
    showResultTab(res);
  }
  if (info.menuItemId === 'ig-scan-link') showResultTab(await scanUrl(info.linkUrl));
  if (info.menuItemId === 'ig-trust') {
    const host = new URL(tab.url).hostname;
    const { trustedSites = [] } = await chrome.storage.local.get('trustedSites');
    if (!trustedSites.includes(host)) trustedSites.push(host);
    await chrome.storage.local.set({ trustedSites });
  }
});

chrome.commands?.onCommand.addListener(async (cmd, tab) => {
  if (cmd === 'scan-page') chrome.tabs.sendMessage(tab.id, { type: 'scan' }).catch(() => { });
  if (cmd === 'reveal-hidden') chrome.tabs.sendMessage(tab.id, { type: 'highlight', on: true }).catch(() => { });
});
