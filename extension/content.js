// InjectGuard content script: reads the live page with real computed styles, splits text into what a person
// can see vs. what is hidden, scans it, reports to the background worker, and can reveal hidden text on request.
(() => {
  if (window.__injectGuardLoaded) return;
  window.__injectGuardLoaded = true;

  const MAX_VISIBLE = 400000;
  let elements = [];          // segment index -> element (for highlighting)
  let lastResult = null;
  let scanTimer = null;
  let lastScanAt = 0;
  let settings = { autoScan: true, showBanner: true, bannerMin: 'malicious' };

  const SKIP = new Set(['SCRIPT', 'STYLE', 'SVG', 'MATH', 'IFRAME', 'OBJECT', 'CANVAS', 'VIDEO', 'AUDIO']);
  const IG_ATTR = 'data-injectguard';

  // ---------------------------------------------------------------- colour helpers
  function parseRGB(s) {
    const m = s && s.match(/rgba?\(([\d.]+)[ ,]+([\d.]+)[ ,]+([\d.]+)(?:[ ,/]+([\d.]+))?/);
    if (!m) return null;
    return { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] };
  }
  function lum(c) {
    const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  }
  function contrast(a, b) {
    const l1 = lum(a), l2 = lum(b);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  }
  function effectiveBg(el) {
    for (let e = el; e && e.nodeType === 1; e = e.parentElement || (e.getRootNode && e.getRootNode().host)) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage && cs.backgroundImage !== 'none') return null;  // image behind: can't judge
      const c = parseRGB(cs.backgroundColor);
      if (c && c.a > 0.5) return c;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  }

  // ---------------------------------------------------------------- why is this element hidden?
  let cache = new WeakMap();     // element -> {reason, root} | null (rebuilt every scan)
  function hiddenInfo(el) {
    if (!el || el.nodeType !== 1) return null;
    if (cache.has(el)) return cache.get(el);
    const parent = el.parentElement || (el.getRootNode && el.getRootNode().host) || null;
    const up = parent ? hiddenInfo(parent) : null;
    if (up) { cache.set(el, up); return up; }
    const own = ownReason(el);
    const info = own ? { reason: own, root: el } : null;
    cache.set(el, info);
    return info;
  }

  function ownReason(el) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none') return el.tagName === 'NOSCRIPT' ? 'inside <noscript>' : 'display:none';
    if (cs.visibility === 'hidden' || cs.visibility === 'collapse') return 'visibility:hidden';
    if (cs.contentVisibility === 'hidden') return 'content-visibility:hidden';
    const op = parseFloat(cs.opacity);
    if (op <= 0.15) return op <= 0.05 ? 'opacity:0' : `nearly transparent (opacity ${op})`;
    if (el.hidden) return 'hidden attribute';
    if (el.getAttribute('aria-hidden') === 'true' && (el.textContent || '').trim().length > 30) return 'aria-hidden';
    const fs = parseFloat(cs.fontSize);
    if (fs < 4) return `font-size ${fs}px`;
    if (fs < 7 && op < 0.5) return `micro text (${fs}px, opacity ${op})`;
    const tf = cs.transform;
    if (tf && tf.startsWith('matrix(')) {
      const v = tf.slice(7, -1).split(',').map(Number);
      if (Math.abs(v[0]) < 0.05 || Math.abs(v[3]) < 0.05) return 'scaled to 0';
    }
    if ((cs.clip && /rect\(\s*0(px)?,?\s+0(px)?/.test(cs.clip)) || /inset\(\s*(50|100)%/.test(cs.clipPath || '')) return 'clipped to nothing';
    if (el.tagName === 'DETAILS' && !el.open) return null;  // collapsed <details>: content handled by display rules
    const r = el.getBoundingClientRect();
    const viewW = Math.max(document.documentElement.clientWidth, innerWidth);
    const absL = r.left + scrollX, absT = r.top + scrollY;
    if (r.width > 0 || r.height > 0) {
      if (absL + r.width <= 0 || absT + r.height <= 0 || absL >= viewW + 500) return 'moved off-screen';
    }
    if ((r.width < 2 || r.height < 2) && (cs.overflow === 'hidden' || cs.overflowX === 'hidden') && (el.textContent || '').trim())
      return 'zero-size box';
    const ti = parseFloat(cs.textIndent);
    if (ti <= -999) return 'text-indent off-screen';
    // colour match: only elements that directly hold text
    if ([...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) {
      const fg = parseRGB(cs.color);
      if (fg && fg.a < 0.1) return 'transparent text';
      const bg = effectiveBg(el);
      if (fg && bg && contrast(fg, bg) < 1.25) return 'text colour matches background';
    }
    return null;
  }

  function describe(el) {
    let s = '<' + el.tagName.toLowerCase();
    if (el.id) s += '#' + el.id;
    if (el.classList && el.classList.length) s += '.' + [...el.classList].slice(0, 2).join('.');
    return s + '>';
  }

  // ---------------------------------------------------------------- collect segments
  function collect() {
    const segs = [];
    elements = [];
    cacheReset();
    const visible = [];
    const codeText = [];
    const groups = new Map();   // root element -> {reason, texts}
    const add = (text, location, visibility, reason, el) => {
      const i = segs.length;
      segs.push({ text, location: `${location} [${i}]`, visibility, hidden_reason: reason || null });
      elements[i] = el || null;
    };

    function walk(rootNode) {
      const tw = document.createTreeWalker(rootNode, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT, {
        acceptNode(n) {
          if (n.nodeType === 1) {
            if (SKIP.has(n.tagName) || n.hasAttribute(IG_ATTR + '-ui')) return NodeFilter.FILTER_REJECT;
            return NodeFilter.FILTER_SKIP;
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      });
      let n;
      while ((n = tw.nextNode())) {
        if (n.nodeType === 8) {
          const t = n.textContent.trim();
          if (t.length > 3) add(t, 'HTML comment', 'comment', 'HTML comment', n.parentElement);
          continue;
        }
        const t = n.textContent;
        if (!t || !t.trim()) continue;
        const el = n.parentElement;
        const info = el.tagName === 'NOSCRIPT' ? { reason: 'inside <noscript>', root: el } : hiddenInfo(el);
        if (info) {
          if (!groups.has(info.root)) groups.set(info.root, { reason: info.reason, texts: [] });
          groups.get(info.root).texts.push(t.trim());
        } else if (el.closest('pre, code')) codeText.push(t.trim());   // shown as an example, not an instruction
        else if (visible.length < MAX_VISIBLE) visible.push(t.trim());
      }
      // open shadow roots
      rootNode.querySelectorAll && rootNode.querySelectorAll('*').forEach(e => { if (e.shadowRoot) walk(e.shadowRoot); });
    }
    walk(document.documentElement);

    for (const [el, g] of groups) add(g.texts.join(' '), describe(el), 'hidden', g.reason, el);
    document.querySelectorAll('template').forEach(t => {
      const txt = (t.content && t.content.textContent || '').trim();
      if (txt.length > 20) add(txt, '<template>', 'hidden', 'inside <template>', t);
    });
    document.querySelectorAll('meta[content]').forEach(m => {
      const c = m.getAttribute('content');
      if (c && c.length > 20) add(c, `<meta ${m.getAttribute('name') || m.getAttribute('property') || ''}>`, 'metadata', 'meta tag', null);
    });
    document.querySelectorAll('[alt],[title],[aria-label],[aria-description],[placeholder],[data-prompt],[data-instructions]').forEach(e => {
      for (const a of ['alt', 'title', 'aria-label', 'aria-description', 'placeholder', 'data-prompt', 'data-instructions']) {
        const v = e.getAttribute(a);
        if (v && v.length > 25) add(v, `${a} on ${describe(e)}`, 'metadata', `${a} attribute`, e);
      }
    });
    // every data-* attribute holding sentence-like text
    document.querySelectorAll('*').forEach(e => {
      for (const at of e.attributes) {
        if (!at.name.startsWith('data-') || at.name === 'data-prompt' || at.name === 'data-instructions') continue;
        const v = at.value;
        if (v && v.length > 40 && /[A-Za-z]{3,} [A-Za-z]{3,}/.test(v))
          add(v, `${at.name} on ${describe(e)}`, 'metadata', `${at.name} attribute`, e);
      }
    });
    document.querySelectorAll('input[type=hidden][value]').forEach(e => {
      const v = e.value;
      if (v && v.length > 20 && /\s/.test(v)) add(v, `hidden input ${e.name || ''}`, 'hidden', 'hidden form field', null);
    });
    if (document.title) add(document.title, '<title>', 'visible', null, null);
    if (visible.length) add(visible.join(' '), 'visible page text', 'visible', null, document.body);
    if (codeText.length) add(codeText.join('\n'), `visible page text: ${self.IG_RULES.code_example_marker || 'code examples'}`, 'visible', null, null);
    return segs;
  }
  function cacheReset() { cache = new WeakMap(); }

  // ---------------------------------------------------------------- scanning
  function scanNow(reason) {
    if (!document.documentElement) return;
    const t0 = performance.now();
    let segs;
    const reveal = document.getElementById(STYLE_ID);   // read the page as it really is, not as we revealed it
    if (reveal && reveal.sheet) reveal.sheet.disabled = true;
    try { segs = collect(); } catch (e) { console.warn('[InjectGuard] collect failed', e); return; }
    finally { if (reveal && reveal.sheet) reveal.sheet.disabled = false; }
    const res = self.InjectGuard.scan(location.href, 'page', segs);
    res.collect_ms = Math.round(performance.now() - t0);
    res.frame = window === top ? 'top' : 'frame';
    lastResult = res;
    lastScanAt = Date.now();
    chrome.runtime.sendMessage({ type: 'pageResult', result: res, segments: segs, reason, url: location.href, title: document.title })
      .catch(() => { });
    return res;
  }

  function scheduleScan(reason, delay) {
    clearTimeout(scanTimer);
    const wait = Math.max(delay, 3000 - (Date.now() - lastScanAt));
    scanTimer = setTimeout(() => scanNow(reason), wait);
  }

  // ---------------------------------------------------------------- reveal / highlight
  const STYLE_ID = 'injectguard-reveal-style';
  function revealStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const st = document.createElement('style');
    st.id = STYLE_ID;
    st.setAttribute(IG_ATTR + '-ui', '');
    st.textContent = `[${IG_ATTR}-reveal]{display:block!important;visibility:visible!important;opacity:1!important;
      position:relative!important;left:auto!important;top:auto!important;clip:auto!important;clip-path:none!important;
      transform:none!important;width:auto!important;height:auto!important;overflow:visible!important;
      font-size:14px!important;text-indent:0!important;color:#7f0000!important;background:#fff0f0!important;
      outline:3px dashed #d32f2f!important;outline-offset:2px!important;margin:6px 0!important;padding:4px!important;
      z-index:2147483646!important}
      [${IG_ATTR}-reveal] *{color:#7f0000!important;font-size:14px!important;visibility:visible!important;opacity:1!important}
      [${IG_ATTR}-reveal]::before{content:attr(${IG_ATTR}-reveal);display:block;font:600 11px system-ui;color:#fff;
      background:#d32f2f;padding:2px 6px;margin-bottom:4px;border-radius:3px}
      [${IG_ATTR}-mark]{outline:3px solid #ef6c00!important;outline-offset:2px!important}`;
    (document.head || document.documentElement).appendChild(st);
  }

  function highlight(on) {
    document.querySelectorAll(`[${IG_ATTR}-reveal],[${IG_ATTR}-mark]`).forEach(e => {
      e.removeAttribute(IG_ATTR + '-reveal'); e.removeAttribute(IG_ATTR + '-mark');
    });
    if (!on || !lastResult) return 0;
    revealStyle();
    let n = 0, first = null;
    const idxOf = loc => { const m = /\[(\d+)\]/.exec(loc || ''); return m ? +m[1] : -1; };
    for (const f of lastResult.findings) {
      if (f.score < self.InjectGuard.thresholds.suspicious) continue;   // skip "hidden, no instructions" notes
      const el = elements[idxOf(f.location)];
      if (!el || el === document.body || el.nodeType !== 1) continue;
      if (el.hasAttribute(IG_ATTR + '-reveal') || el.hasAttribute(IG_ATTR + '-mark')) continue;  // findings are sorted: keep the top one
      if (f.visibility === 'hidden') {
        el.setAttribute(IG_ATTR + '-reveal', `InjectGuard: hidden (${f.hidden_reason || 'hidden'}) — ${f.title} [${f.score}]`);
      } else el.setAttribute(IG_ATTR + '-mark', '');
      n++;
      first = first || el;
    }
    if (first) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return n;
  }

  // ---------------------------------------------------------------- warning banner (isolated in shadow DOM)
  function banner(res) {
    const old = document.getElementById('injectguard-banner');
    if (old) old.remove();
    if (!settings.showBanner || window !== top) return;
    const order = { clean: 0, suspicious: 1, malicious: 2 };
    if (order[res.verdict] < order[settings.bannerMin || 'malicious']) return;
    const host = document.createElement('div');
    host.id = 'injectguard-banner';
    host.setAttribute(IG_ATTR + '-ui', '');
    host.style.cssText = 'all:initial;position:fixed;top:12px;right:12px;z-index:2147483647';
    const sh = host.attachShadow({ mode: 'closed' });
    const color = res.verdict === 'malicious' ? '#c62828' : '#ef6c00';
    const hidden = new Set(res.findings.filter(f => f.visibility !== 'visible' && f.score >= 20).map(f => f.location)).size;
    sh.innerHTML = `<style>
      .b{font:13px/1.4 system-ui,sans-serif;background:#fff;color:#222;border-left:6px solid ${color};border-radius:8px;
      box-shadow:0 4px 18px rgba(0,0,0,.25);padding:12px 14px;max-width:340px}
      .t{font-weight:700;color:${color};margin-bottom:4px} button{font:600 12px system-ui;margin:8px 6px 0 0;padding:5px 10px;
      border-radius:5px;border:1px solid #bbb;background:#f5f5f5;cursor:pointer} button.p{background:${color};color:#fff;border-color:${color}}</style>
      <div class="b" role="alert"><div class="t">⚠ InjectGuard: ${res.verdict.toUpperCase()} page (score ${res.score})</div>
      <div>This page ${hidden ? `hides ${hidden} block${hidden > 1 ? 's' : ''} of text` : 'contains text'} aimed at AI tools.
      Don't ask an AI assistant to read or summarize it until you've checked.</div>
      <button class="p" id="show">Show hidden text</button><button id="close">Dismiss</button></div>`;
    sh.getElementById('show').onclick = () => highlight(true);
    sh.getElementById('close').onclick = () => host.remove();
    document.documentElement.appendChild(host);
  }

  // ---------------------------------------------------------------- messages
  chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    if (msg.type === 'scan') { reply(scanNow('manual')); return; }
    if (msg.type === 'highlight') { reply({ count: highlight(msg.on !== false) }); return; }
    if (msg.type === 'getResult') { reply(lastResult); return; }
    if (msg.type === 'finalResult') {           // result after the desktop engine had its say
      lastResult = { ...msg.result, findings: msg.result.findings };
      banner(lastResult);
      return;
    }
    if (msg.type === 'scanSelection') {
      const sel = String(getSelection() || '');
      reply(sel ? self.InjectGuard.scan('Selected text', 'text', [{ text: sel, location: 'selection [0]', visibility: 'visible' }]) : null);
      return;
    }
  });

  function isOwn(n) {
    return n && n.nodeType === 1 && (n.hasAttribute(IG_ATTR + '-ui') || n.id === 'injectguard-banner');
  }
  function isOwnMutation(m) {
    if (m.type === 'childList') {
      const nodes = [...m.addedNodes, ...m.removedNodes];
      return nodes.length > 0 && nodes.every(isOwn);
    }
    const t = m.target.nodeType === 1 ? m.target : m.target.parentElement;
    return !!(t && t.closest && t.closest(`[${IG_ATTR}-ui]`));
  }

  // ---------------------------------------------------------------- auto-scan
  chrome.storage.local.get(['settings', 'trustedSites']).then(({ settings: s, trustedSites }) => {
    settings = { ...settings, ...(s || {}) };
    const host = location.hostname;
    if ((trustedSites || []).includes(host)) return;
    if (!settings.autoScan) return;
    const start = () => {
      scheduleScan('load', 600);
      const mo = new MutationObserver(muts => {
        if (muts.some(m => !isOwnMutation(m))) scheduleScan('change', 1500);
      });
      mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true,
        attributeFilter: ['style', 'class', 'hidden'] });
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  });
})();
