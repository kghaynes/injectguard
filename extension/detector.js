// InjectGuard rule engine for the browser. Same logic as injectguard/rules.py, same rules (rules.js).
// Works in content scripts, the popup, and the service worker.
(function (root) {
  const R = root.IG_RULES;
  const MULT = R.visibility_multiplier;
  const TH = R.thresholds;
  const TIERS = R.hidden_reason_multiplier || [];
  const DUP_MIN = R.duplicate_min_chars || 20;
  const COMBO = R.combo;
  const VISIBLE_CAP = R.visible_only_cap ?? 45;
  const CODE_MARK = R.code_example_marker || 'code examples';
  const INVISIBLE_FAMILIES = new Set(['invisible_unicode', 'encoded_payload']);
  // Text that addresses an AI *and* tells it to do something is an injection however it is worded.
  function comboFinding(hits, seg) {
    if (!COMBO || !hits.length) return null;
    const addr = hits.filter(h => COMBO.addressing.includes(h.rule_id.split(':').pop()));
    const acts = hits.filter(h => COMBO.action_families.includes(h.family));
    if (!addr.length || !acts.length) return null;
    const top = hits.reduce((a, h) => h.score > a.score ? h : a);
    const bonus = seg.visibility === 'visible' ? COMBO.bonus_visible : COMBO.bonus_hidden;
    return {
      rule_id: 'CMB-001', family: 'combination', title: 'Addresses an AI and tells it to act',
      explain: `This text speaks to AI tools (${addr[0].title.toLowerCase()}) and gives them an instruction (${acts[0].title.toLowerCase()}). That pairing is what makes text a prompt injection.`,
      score: Math.min(100, top.score + bonus), excerpt: top.excerpt, location: seg.location,
      visibility: seg.visibility, hidden_reason: seg.hidden_reason || null
    };
  }
  function multiplier(vis, reason) {
    if (vis === 'hidden' && reason) {
      const r = String(reason).toLowerCase();
      for (const t of TIERS) if (t.prefixes.some(p => r.startsWith(p))) return t.mult;
    }
    return MULT[vis] || 1;
  }
  const PHRASE = R.phrase_rules.map(r => ({ ...r, rx: new RegExp(r.pattern, 'is' + (r.flags || '').replace(/[^m]/g, '')) }));

  const ZW = new Set([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD, 0x034F, 0x2061, 0x2062, 0x2063, 0x2064]);
  const isBidi = cp => (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200E || cp === 0x200F || cp === 0x061C;
  const isTag = cp => cp >= 0xE0000 && cp < 0xE0080;
  const isVar = cp => (cp >= 0xFE00 && cp < 0xFE10) || (cp >= 0xE0100 && cp < 0xE01F0);
  const isInvisible = cp => ZW.has(cp) || isBidi(cp) || isTag(cp) || isVar(cp);

  const HOMO = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g',
    'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ν': 'v', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't',
    'υ': 'u', 'χ': 'x', 'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm', 'Н': 'h', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't',
    'Х': 'x', 'І': 'i', 'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Η': 'h', 'Ι': 'i', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o', 'Ρ': 'p',
    'Τ': 't', 'Χ': 'x'
  };

  // Lower-case, NFKC, drop invisible chars, fold look-alikes, collapse spaces. idx maps each output char to a raw index.
  function normalize(raw) {
    const out = [], idx = [];
    let prevSpace = true, i = 0;
    for (const ch of raw) {
      const cp = ch.codePointAt(0);
      const at = i;
      i += ch.length;
      if (isInvisible(cp)) continue;
      for (let c of ch.normalize('NFKC')) {
        c = (HOMO[c] || c).toLowerCase();
        if (/\s/.test(c)) {
          if (prevSpace) continue;
          c = ' ';
          prevSpace = true;
        } else prevSpace = false;
        for (const u of c) { out.push(u); idx.push(at); }
      }
    }
    return [out.join(''), idx];
  }

  function stripInvisible(s) {
    let o = '';
    for (const ch of s) if (!isInvisible(ch.codePointAt(0))) o += ch;
    return o;
  }

  function excerpt(raw, a0, b0, ctx = 60) {
    const a = Math.max(0, a0 - ctx), b = Math.min(raw.length, b0 + ctx);
    let s = stripInvisible(raw.slice(a, b)).replace(/\s+/g, ' ').trim();
    if (a > 0) s = '…' + s;
    if (b < raw.length) s += '…';
    return s.slice(0, 300);
  }

  // True when the match sits inside an open quotation (someone quoting the attack, not making it).
  function isQuoted(raw, s, e, span = 300) {
    const before = raw.slice(Math.max(0, s - span), s), after = raw.slice(e, e + span);
    if ((before.split('"').length - 1) % 2 === 1 && after.includes('"')) return true;
    for (const [o, c] of [['“', '”'], ['‘', '’'], ['«', '»']])
      if (before.lastIndexOf(o) > before.lastIndexOf(c) && after.includes(c)) return true;
    const qb = before.lastIndexOf("'");
    return qb >= before.length - 3 && after.slice(0, 120).includes("'");
  }

  const score = (w, vis, reason) => Math.min(100, Math.round(w * multiplier(vis, reason)));

  function phrase(raw, seg, extra = 0, prefix = '', famOverride = null, titlePrefix = '') {
    const [norm, idx] = normalize(raw);
    const found = [];
    for (const r of PHRASE) {
      r.rx.lastIndex = 0;
      const text = r.raw ? raw : norm;
      const m = r.rx.exec(text);
      if (!m) continue;
      let rs, re;
      if (r.raw) { rs = m.index; re = m.index + m[0].length; } else {
        rs = idx[m.index] ?? 0;
        const last = m.index + m[0].length - 1;
        re = last < idx.length ? idx[last] + 1 : raw.length;
      }
      let w = r.weight + extra, title = titlePrefix + r.title, explain = r.explain;
      let hasInv = false;
      if (!r.raw) for (const ch of raw.slice(rs, re)) if (isInvisible(ch.codePointAt(0))) { hasInv = true; break; }
      if (hasInv) {
        w += 20; title += ' (split with invisible characters)';
        explain += ' Invisible characters were inserted inside the words to slip past filters.';
      } else if (seg.visibility === 'visible' && String(seg.location || '').endsWith(CODE_MARK)) {
        w = Math.floor(w * 0.4); title += ' (in a code example)';
      } else if (seg.visibility === 'visible' && isQuoted(raw, rs, re)) {
        w = Math.floor(w * 0.4); title += ' (quoted - likely a discussion)';
      }
      found.push({
        rule_id: prefix + r.id, family: famOverride || r.family, title, explain, score: score(w, seg.visibility, seg.hidden_reason),
        excerpt: excerpt(raw, rs, re), location: seg.location, visibility: seg.visibility,
        hidden_reason: seg.hidden_reason || (hasInv ? 'split with invisible characters' : null)
      });
    }
    return found;
  }

  const ZW_CODE = new Set([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]);
  const plausible = t => t.length >= 4 && [...t].filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length / t.length >= 0.9
    && t.includes(' ') && /[A-Za-z]{3,}/.test(t);
  // Decode text hidden as binary in zero-width characters (two symbols = 0/1, optional third = separator).
  function decodeZeroWidth(raw) {
    let zw = [...raw].filter(c => ZW_CODE.has(c.codePointAt(0)));
    if (raw.startsWith('\uFEFF')) zw = zw.slice(1);
    if (zw.length < 16) return '';
    const count = c => zw.filter(x => x === c).length;
    const syms = [...new Set(zw)].sort((a, b) => count(b) - count(a));
    if (syms.length < 2) return '';   // one repeated character carries no binary message
    let best = '';
    const take = t => { if (plausible(t) && t.length > best.length) best = t; };
    if (syms.length >= 3) {
      for (const sep of syms) {
        const bits = syms.filter(c => c !== sep).slice(0, 2);
        for (const [zero, one] of [bits, [bits[1], bits[0]]]) {
          const groups = zw.join('').split(sep).filter(g => g && [...g].every(c => c === zero || c === one));
          take(groups.map(g => String.fromCharCode(parseInt([...g].map(c => c === zero ? '0' : '1').join(''), 2))).join(''));
        }
      }
    }
    for (const [zero, one] of [[syms[0], syms[1]], [syms[1], syms[0]]]) {
      const stream = zw.filter(c => c === zero || c === one).map(c => c === zero ? '0' : '1').join('');
      for (const w of [8, 7]) {
        let t = '';
        for (let i = 0; i + w <= stream.length; i += w) t += String.fromCharCode(parseInt(stream.slice(i, i + w), 2));
        take(t);
      }
    }
    return best;
  }

  function checkUnicode(raw, seg) {
    const f = [], extra = [];
    let zw = 0, bidi = 0, tags = [], first = { zw: -1, bidi: -1, tag: -1 }, i = 0;
    const body = raw.startsWith('﻿') ? 1 : 0;
    for (const ch of raw) {
      const cp = ch.codePointAt(0);
      if (ZW.has(cp) && i >= body) { zw++; if (first.zw < 0) first.zw = i; }
      if (isBidi(cp)) { bidi++; if (first.bidi < 0) first.bidi = i; }
      if (isTag(cp)) { tags.push(cp); if (first.tag < 0) first.tag = i; }
      i += ch.length;
    }
    if (tags.length) {
      const dec = tags.map(c => c - 0xE0000).filter(c => c >= 0x20 && c <= 0x7E).map(c => String.fromCharCode(c)).join('');
      f.push({
        rule_id: 'UNI-TAG', family: 'invisible_unicode', title: 'Hidden message in invisible Unicode tag characters',
        explain: 'Unicode tag characters (U+E0000 block) show nothing on screen but many AI models read them as normal letters. This is called ASCII smuggling.',
        score: Math.min(100, 50 + (dec.length > 10 ? 20 : 0)), excerpt: dec ? 'Decoded: ' + dec.slice(0, 250) : excerpt(raw, first.tag, first.tag + 1),
        location: seg.location, visibility: seg.visibility, hidden_reason: 'invisible Unicode tags'
      });
      if (dec.trim()) extra.push({ text: dec, location: seg.location + ' (decoded tag characters)', visibility: 'hidden', hidden_reason: 'invisible Unicode tags' });
    }
    const zdec = zw >= 16 ? decodeZeroWidth(raw) : '';
    if (zdec) {
      f.push({
        rule_id: 'UNI-ZWD', family: 'invisible_unicode', title: 'Hidden message encoded in zero-width characters',
        explain: 'A run of invisible zero-width characters spells out text in binary. People see nothing; tools that decode it, including some AI pipelines, read a message.',
        score: Math.min(100, 50 + (zdec.length > 10 ? 20 : 0)), excerpt: 'Decoded: ' + zdec.slice(0, 250),
        location: seg.location, visibility: seg.visibility, hidden_reason: 'zero-width encoding'
      });
      extra.push({ text: zdec, location: seg.location + ' (decoded zero-width characters)', visibility: 'hidden', hidden_reason: 'zero-width encoding' });
    } else if (zw >= 3) f.push({
      rule_id: 'UNI-ZW', family: 'invisible_unicode', title: `${zw} zero-width characters (no hidden message)`,
      explain: 'Zero-width characters are invisible. They are used to split banned words so filters miss them, or to watermark text.',
      score: 8, excerpt: excerpt(raw, first.zw, first.zw + 1), location: seg.location, visibility: seg.visibility, hidden_reason: seg.hidden_reason || null
    });
    if (bidi) f.push({
      rule_id: 'UNI-BIDI', family: 'invisible_unicode', title: `${bidi} text-direction override characters`,
      explain: 'Bidirectional override characters make text display in a different order than the AI reads it.',
      score: 8, excerpt: excerpt(raw, first.bidi, first.bidi + 1), location: seg.location, visibility: seg.visibility, hidden_reason: seg.hidden_reason || null
    });
    return [f, extra];
  }

  const B64 = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])/g;
  function checkBase64(raw, seg) {
    const out = [];
    B64.lastIndex = 0;
    let m, n = 0;
    while ((m = B64.exec(raw)) && n++ < 200) {
      const blob = m[0];
      if (blob.length > 20000) continue;
      let txt;
      try {
        const bin = atob(blob + '='.repeat((4 - blob.length % 4) % 4));
        txt = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
      } catch (e) { continue; }
      if (!txt) continue;
      let printable = 0;
      for (const c of txt) if (!/[\x00-\x08\x0e-\x1f\x7f]/.test(c)) printable++;
      if (printable / txt.length < 0.9 || !/[A-Za-z]{3,} [A-Za-z]{2,}/.test(txt)) continue;
      out.push(...phrase(txt, { ...seg, location: seg.location + ' (decoded Base64)' }, 10, 'B64:', 'encoded_payload', 'Base64-encoded: '));
    }
    return out;
  }

  function checkHomoglyphs(raw, seg) {
    const words = raw.match(/\p{L}{3,}/gu) || [];
    const mixed = words.filter(w => /[A-Za-z]/.test(w) && /[Ͱ-ϿЀ-ӿ]/.test(w));
    if (mixed.length < 2) return [];
    return [{
      rule_id: 'HOM-001', family: 'homoglyph', title: `${mixed.length} words mix Latin with look-alike letters`,
      explain: 'Words that mix English letters with Cyrillic or Greek look-alikes are a trick to slip past keyword filters.',
      score: mixed.length < 5 ? 15 : 25, excerpt: mixed.slice(0, 8).join(', '), location: seg.location,
      visibility: seg.visibility, hidden_reason: seg.hidden_reason || null
    }];
  }

  // Hidden text that also appears on screen is a layout copy, not camouflage: treat it as visible.
  function demoteDuplicates(segments) {
    const visible = segments.filter(s => s.visibility === 'visible').map(s => normalize(s.text || '')[0]).join(' ');
    if (!visible) return segments.slice();
    return segments.map(s => {
      if (s.visibility !== 'hidden') return s;
      const n = normalize(s.text || '')[0].trim();
      return n.length >= DUP_MIN && visible.includes(n) ? { ...s, visibility: 'visible', hidden_reason: null } : s;
    });
  }

  function scanSegments(segments) {
    const findings = [];
    const queue = demoteDuplicates(segments);
    let n = 0;
    while (queue.length) {
      const seg = queue.shift();
      const raw = seg.text || '';
      if (!raw.trim()) continue;
      n++;
      const [uni, extra] = checkUnicode(raw, seg);
      findings.push(...uni);
      queue.push(...extra);
      const hits = [...phrase(raw, seg), ...checkBase64(raw, seg), ...checkHomoglyphs(raw, seg)];
      findings.push(...hits);
      const combo = comboFinding(hits, seg);
      if (combo) findings.push(combo);
      if (seg.visibility === 'hidden' && !hits.length && !uni.length && normalize(raw)[0].length >= 40) {
        findings.push({
          rule_id: 'HID-INFO', family: 'hidden_text', title: 'Hidden text (no instructions found)',
          explain: 'This text is hidden from people but readable by AI tools. Nothing in it matched an injection rule.',
          score: 8, excerpt: excerpt(raw, 0, Math.min(raw.length, 200), 0), location: seg.location,
          visibility: seg.visibility, hidden_reason: seg.hidden_reason || null
        });
      }
    }
    return [dedupe(findings), n];
  }

  // One finding per rule per piece of text: the same sentence in several places counts once.
  function dedupe(fs) {
    const best = new Map(), places = new Map();
    for (const f of fs) {
      const k = f.rule_id + '|' + normalize(f.excerpt)[0].slice(0, 80);
      if (!places.has(k)) places.set(k, new Set());
      places.get(k).add(f.location);
      if (!best.has(k) || best.get(k).score < f.score) best.set(k, f);
    }
    const out = [];
    for (const [k, f0] of best) {
      const f = { ...f0 }, n = places.get(k).size - 1;
      if (n > 0) {
        const m = /\s*(\[\d+\])$/.exec(f.location);
        const loc = m ? f.location.slice(0, m.index) : f.location;
        f.location = `${loc} (+${n} more place${n > 1 ? 's' : ''})${m ? ' ' + m[1] : ''}`;
      }
      out.push(f);
    }
    return out.sort((a, b) => b.score - a.score);
  }

  function overall(fs) {
    if (!fs.length) return [0, 'clean'];
    const s = fs.map(f => f.score).sort((a, b) => b - a);
    const extra = s.slice(1).filter(x => x >= TH.suspicious).length;
    let sc = Math.min(100, s[0] + 8 * Math.min(extra, 6));
    // Everything in plain view: the reader can see it for themselves, so at most "suspicious".
    const hidden = f => f.visibility !== 'visible' || !!f.hidden_reason || INVISIBLE_FAMILIES.has(f.family) || /^B64:/.test(f.rule_id);
    if (!fs.some(f => f.score >= TH.suspicious && hidden(f))) sc = Math.min(sc, VISIBLE_CAP);
    return [sc, sc >= TH.malicious ? 'malicious' : sc >= TH.suspicious ? 'suspicious' : 'clean'];
  }

  function scan(target, kind, segments) {
    const t0 = Date.now();
    const [findings, n] = scanSegments(segments);
    const [sc, verdict] = overall(findings);
    return {
      target, kind, verdict, score: sc, findings, segments_scanned: n, errors: [], duration_ms: Date.now() - t0,
      scanned_at: new Date().toISOString(), engine: 'browser'
    };
  }

  root.InjectGuard = { scan, scanSegments, overall, normalize, thresholds: TH };
})(typeof self !== 'undefined' ? self : globalThis);
