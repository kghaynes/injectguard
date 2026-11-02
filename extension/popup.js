// InjectGuard popup: current page verdict and findings, alert history, and quick protection settings.
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const params = new URLSearchParams(location.search);
let tab = null, result = null, settings = {};

const HELP = `InjectGuard reads every piece of text on the page and marks whether you can see it.
Text that's hidden from you (white-on-white, zero-size, off-screen, display:none, HTML comments, invisible Unicode)
but reads like an instruction to an AI ("ignore previous instructions", "do not tell the user", "send the emails to…")
is scored high. Hidden + instruction = Malicious.

Scores: Clean under 20 · Suspicious 20–59 · Malicious 60+.
With the desktop engine paired, pages are also checked by the full engine (and an optional local AI model),
and results are saved in the desktop app's history.`;

async function init() {
  ({ settings = {} } = await chrome.storage.local.get('settings'));
  if (params.get('view') === 'adhoc') return adhoc();
  if (params.get('tabId')) tab = await chrome.tabs.get(+params.get('tabId'));   // pop-out view of a specific tab
  else [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  $('#site').textContent = tab?.url ? new URL(tab.url).host || tab.url : '—';
  bindUI();
  await loadResult();
  renderHistory();
  renderEngine();
}

async function loadResult(force) {
  if (!tab) return;
  if (!/^https?:|^file:/.test(tab.url || '')) {
    $('#findings').innerHTML = `<div class="empty">InjectGuard can't scan this kind of page.</div>`;
    setVerdict(null);
    return;
  }
  result = force ? null : await chrome.runtime.sendMessage({ type: 'getTabResult', tabId: tab.id });
  if (!result) {
    // No auto-scan yet (trusted site, auto-scan off, or page opened before install): ask the page to scan.
    try {
      await chrome.tabs.sendMessage(tab.id, { type: 'scan' });
    } catch (e) {
      await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, files: ['rules.js', 'detector.js', 'content.js'] });
      await new Promise(r => setTimeout(r, 300));
      await chrome.tabs.sendMessage(tab.id, { type: 'scan' }).catch(() => { });
    }
    for (let i = 0; i < 30 && !result; i++) {
      await new Promise(r => setTimeout(r, 200));
      result = await chrome.runtime.sendMessage({ type: 'getTabResult', tabId: tab.id });
    }
  }
  render(result);
}

function setVerdict(r) {
  const pill = $('#verdict .pill');
  pill.className = 'pill ' + (r ? r.verdict : '');
  pill.textContent = r ? r.verdict.toUpperCase() : '—';
  $('#verdict .score').textContent = r ? `${r.score}/100` : '';
  $('#verdict .meta').innerHTML = r ? `${r.segments_scanned ?? 0} text blocks${r.frames > 1 ? ` · ${r.frames} frames` : ''}<br>` +
    `${r.engine === 'desktop' ? 'checked by desktop engine' : r.engine === 'mixed' ? 'desktop + browser checks' : 'in-browser checks'}` : '';
}

// One card per place on the page: a hidden block often trips several rules at once.
function groupHTML(fs) {
  const f = fs[0];
  const top = Math.max(...fs.map(x => x.score));
  const cls = top >= 60 ? 'hi' : top >= 20 ? 'mid' : '';
  const vis = f.visibility === 'visible' ? '<span class="tag">visible</span>' :
    `<span class="tag hidden">${esc(f.visibility)}${f.hidden_reason ? ': ' + esc(f.hidden_reason) : ''}</span>`;
  const ai = fs.filter(x => x.llm_verdict).map(x => `<div class="w">Local AI: ${esc(x.llm_verdict)} — ${esc(x.llm_reason || '')}</div>`).join('');
  const loc = String(f.location || '').replace(/\s*\[\d+\]$/, '');
  const longest = fs.reduce((a, x) => x.excerpt.length > a.length ? x.excerpt : a, '');
  const more = fs.slice(1).map(x => `<li>${esc(x.title)} <span class="muted">${x.score}</span></li>`).join('');
  return `<div class="f ${cls}"><div class="t">${esc(f.title)}<span>${top}</span></div>
    ${more ? `<ul class="also">${more}</ul>` : ''}
    <div class="w">${vis} ${esc(loc)}${f.frame === 'frame' ? ' · inside a frame' : ''}</div>
    <code>${esc(longest)}</code>${ai}
    <details><summary>Why this matters</summary>${fs.map(x => `<div class="why"><b>${esc(x.title)}:</b> ${esc(x.explain)}
    <span class="w">(${esc(x.rule_id)})</span></div>`).join('')}</details></div>`;
}

function grouped(list) {
  const m = new Map();
  for (const f of list) {
    const k = (f.frame || '') + '|' + f.location;
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(f);
  }
  return [...m.values()];
}

function render(r) {
  setVerdict(r);
  if (!r) { $('#findings').innerHTML = `<div class="empty">No result yet. Press Re-scan.</div>`; return; }
  r.findings = r.findings || [];
  const info = r.findings.filter(f => f.rule_id === 'HID-INFO');
  const main = r.findings.filter(f => f.rule_id !== 'HID-INFO');
  $('#infoCount').textContent = info.length;
  const list = $('#showInfo').checked ? r.findings : main;
  const errs = (r.errors || []).map(e => `<div class="w">⚠ ${esc(e)}</div>`).join('');
  $('#findings').innerHTML = errs + (list.length ? grouped(list).map(groupHTML).join('') :
    `<div class="empty">No hidden instructions found on this page.</div>`);
  $('#foot').textContent = r.scanned_at ? `Scanned ${new Date(r.scanned_at).toLocaleTimeString()} · ${r.duration_ms} ms` : '';
}

async function renderHistory() {
  const { history = [] } = await chrome.storage.local.get('history');
  $('#history').innerHTML = history.length ? history.slice(0, 60).map(h => `<div class="h">
    <span class="pill ${h.verdict}">${h.verdict.toUpperCase()}</span> <b>${h.score}</b> · ${new Date(h.at).toLocaleString()}
    <div>${esc(h.title || '')}</div><div class="u">${esc(h.url)}</div>
    <div class="w muted">${h.top.map(t => esc(t.title) + (t.hidden_reason ? ' (' + esc(t.hidden_reason) + ')' : '')).join(' · ')}</div></div>`).join('')
    : `<div class="empty">No flagged pages yet.</div>`;
}

async function renderEngine() {
  const st = await chrome.runtime.sendMessage({ type: 'engineStatus' });
  $('#engine').innerHTML = `<div><span class="dot ${st.ok ? 'ok' : st.reachable ? 'warn' : ''}"></span><b>Desktop engine</b></div>
    <div class="muted">${esc(st.msg)}</div>` + (st.ok ? `<div class="muted">Local AI check: ${st.status.llm_enabled ? 'on' : 'off'} ·
    Folder watch: ${st.status.realtime ? 'on' : 'off'}</div>` : '');
  const s = { autoScan: true, showBanner: true, notify: true, useEngine: true, ...settings };
  for (const k of ['autoScan', 'showBanner', 'notify', 'useEngine']) $('#' + k).checked = !!s[k];
  const { trustedSites = [] } = await chrome.storage.local.get('trustedSites');
  const host = tab?.url ? new URL(tab.url).hostname : '';
  $('#trustState').textContent = host ? (trustedSites.includes(host) ? `${host} is trusted (not auto-scanned).` : `${host} is scanned automatically.`) : '';
}

async function setSetting(k, v) {
  settings = { ...settings, [k]: v };
  await chrome.storage.local.set({ settings });
}

async function act(a) {
  $('#menu').hidden = true;
  if (a === 'rescan') { $('#findings').innerHTML = '<div class="empty">Scanning…</div>'; await loadResult(true); }
  if (a === 'reveal') { const r = await chrome.tabs.sendMessage(tab.id, { type: 'highlight', on: true }).catch(() => null); $('#foot').textContent = r ? `Revealed ${r.count} element(s) on the page.` : 'Could not reach the page.'; }
  if (a === 'hide') chrome.tabs.sendMessage(tab.id, { type: 'highlight', on: false }).catch(() => { });
  if (a === 'selection') {
    const [{ result: sel } = {}] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => String(getSelection()) }).catch(() => [{}]);
    if (!sel) { $('#foot').textContent = 'Select some text on the page first.'; return; }
    render(await chrome.runtime.sendMessage({ type: 'scanText', text: sel }));
  }
  if (a === 'trust' || a === 'untrust') {
    const host = new URL(tab.url).hostname;
    let { trustedSites = [] } = await chrome.storage.local.get('trustedSites');
    trustedSites = a === 'trust' ? [...new Set([...trustedSites, host])] : trustedSites.filter(h => h !== host);
    await chrome.storage.local.set({ trustedSites });
    renderEngine();
    $('#foot').textContent = a === 'trust' ? `${host} will no longer be scanned automatically.` : `${host} will be scanned automatically.`;
  }
  if (a === 'copy' && result) {
    await navigator.clipboard.writeText(`${result.verdict.toUpperCase()} ${result.score} ${result.target}\n` +
      result.findings.map(f => `[${f.score}] ${f.title} | ${f.visibility}${f.hidden_reason ? ' (' + f.hidden_reason + ')' : ''} | ${f.excerpt}`).join('\n'));
    $('#foot').textContent = 'Copied.';
  }
  if (a === 'export' && result) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }));
    const el = document.createElement('a');
    el.href = url; el.download = `injectguard-${new URL(result.target).hostname}.json`; el.click();
  }
  if (a === 'options') chrome.runtime.openOptionsPage();
  if (a === 'help') { $('#findings').innerHTML = `<div class="card" style="white-space:pre-wrap">${esc(HELP)}</div>`; switchTab('page'); }
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.pane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
}

function bindUI() {
  $('#menuBtn').onclick = e => { e.stopPropagation(); $('#menu').hidden = !$('#menu').hidden; };
  document.addEventListener('click', e => { if (!$('#menu').contains(e.target)) $('#menu').hidden = true; });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#menu').hidden = true; });
  document.querySelectorAll('#menu button').forEach(b => b.onclick = () => act(b.dataset.act));
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => switchTab(t.dataset.tab));
  $('#rescan').onclick = () => act('rescan');
  $('#reveal').onclick = () => act('reveal');
  $('#showInfo').onchange = () => render(result);
  $('#clearHist').onclick = async () => { await chrome.storage.local.set({ history: [] }); renderHistory(); };
  $('#openOptions').onclick = () => chrome.runtime.openOptionsPage();
  for (const k of ['autoScan', 'showBanner', 'notify', 'useEngine']) $('#' + k).onchange = e => setSetting(k, e.target.checked);
}

async function adhoc() {
  document.body.classList.add('full');
  document.querySelector('nav').remove();
  $('#menuBtn').remove();
  const { lastAdHoc } = await chrome.storage.session.get('lastAdHoc');
  $('#site').textContent = lastAdHoc ? lastAdHoc.target : '';
  document.querySelector('.actions').remove();
  $('#showInfo').onchange = () => render(lastAdHoc);
  result = lastAdHoc;
  render(lastAdHoc);
}

init();
