(() => {
'use strict';
const d = document, html = d.documentElement;
const $ = (s, p) => (p || d).querySelector(s);
const $$ = (s, p) => Array.from((p || d).querySelectorAll(s));
const BW = JSON.parse($('#bw').textContent);

/* ---------- the dock: a copy of the bar, made before anything is wired to its links ---------- */
const nav = $('#nav');
const dock = nav.cloneNode(true);
dock.id = 'dock'; dock.classList.add('dockbar'); nav.classList.add('top');
d.body.append(dock);
let docked = false;
function setDock(on) {
  docked = on;
  html.classList.toggle('docked', on);
  dock.inert = !on; nav.inert = on;   // whichever of the two is out of sight is also out of reach
}
setDock(false);
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const ease = t => 1 - Math.pow(1 - t, 3);

/* ---------- language: a manual choice always wins on the next visit ---------- */

$$('[data-lang]').forEach(a => a.addEventListener('click', () => {
  try { localStorage.setItem('bw-lang', a.dataset.lang); } catch (e) {}
}));

/* ---------- system ---------- */
const OS = (() => {
  const u = navigator.userAgent;
  const p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
  if (/Android/i.test(u)) return 'android';
  if (/iPhone|iPad|iPod/i.test(u) || (/Mac/i.test(p) && navigator.maxTouchPoints > 1)) return 'ios';
  if (/Mac/i.test(p)) return 'mac';
  if (/Win/i.test(p)) return 'win';
  if (/Linux|X11/i.test(p)) return 'linux';
  return 'other';
})();
const OURS = OS === 'mac' || OS === 'win' || OS === 'linux' || OS === 'android';
const ARCH = { mac: 'Apple Silicon', win: 'Windows x64', linux: 'Linux x64', android: 'Android 10+' };

/* ---------- visits and downloads: counted by the worker, without cookies ---------- */
const quiet = navigator.doNotTrack === '1' || navigator.globalPrivacyControl === true;
function beacon(o) {
  if (!BW.worker || quiet) return;
  try { navigator.sendBeacon(BW.worker + '/hit', JSON.stringify(o)); } catch (e) {}
}
let ref = '';
try { if (d.referrer) { const h = new URL(d.referrer).hostname; if (h !== location.hostname) ref = h; } } catch (e) {}
beacon({ t: 'view', p: BW.page, l: BW.lang, o: OS, r: ref });
$$('[data-dl]').forEach(a => a.addEventListener('click', () => beacon({ t: 'dl', l: BW.lang, o: a.dataset.dl })));

/* ---------- releases: baked in at build time, refreshed through the worker ---------- */
const nf = new Intl.NumberFormat(BW.lang);
const mb = (bytes, unit) => bytes ? (bytes / 1e6).toFixed(1) + ' ' + unit : '';
let counted = false;

function countUp(el, to) {
  if (reduce || !to) { el.textContent = nf.format(to); return; }
  const t0 = performance.now();
  (function step(now) {
    const k = clamp((now - t0) / 1400, 0, 1);
    el.textContent = nf.format(Math.round(to * ease(k)));
    if (k < 1) requestAnimationFrame(step);
  })(t0);
}

function applyReleases(rel) {
  if (!rel || !rel.files || !rel.files[BW.lang]) return;
  const files = rel.files[BW.lang];
  $$('[data-dl]').forEach(a => { if (files[a.dataset.dl]) a.href = files[a.dataset.dl].url; });
  $$('[data-size]').forEach(el => { el.textContent = mb((files[el.dataset.size] || {}).size, el.dataset.mb); });
  $$('[data-ver]').forEach(el => { el.textContent = 'v' + rel.version; });

  const cta = $('#cta'), meta = $('#cta-meta');
  if (cta && OURS && files[OS]) {
    cta.href = files[OS].url;
    cta.dataset.dl = OS;
    cta.textContent = cta.dataset[OS];
    meta.textContent = ['v' + rel.version, mb(files[OS].size, meta.dataset.mb), ARCH[OS]].filter(Boolean).join(' · ');
    $('#cta-all').hidden = false;
  } else if (meta) {
    meta.textContent = 'v' + rel.version + ' · macOS · Windows · Linux · Android';
  }

  const dl = rel.downloads, box = $('#count');
  if (dl && dl.total > 0 && box) {
    box.hidden = false;
    $$('[data-count]').forEach(el => {
      const n = dl[el.dataset.count] || 0;
      if (el.id === 'count-n') { el.dataset.to = n; if (counted) el.textContent = nf.format(n); }
      else el.textContent = n ? '↓ ' + nf.format(n) : '';
    });
  }
}
const cta = $('#cta');
if (cta) cta.addEventListener('click', () => { if (cta.dataset.dl) beacon({ t: 'dl', l: BW.lang, o: cta.dataset.dl }); });
$$('.plat').forEach(el => el.classList.toggle('me', el.dataset.os === OS));
applyReleases(BW.releases);
// a page that came through the worker already carries the current releases and statistics
if (BW.worker && !BW.fresh) {
  fetch(BW.worker + '/releases').then(r => r.ok ? r.json() : null).then(applyReleases).catch(() => {});
}

/* ---------- benchmarks: the numbers of tools/bench/run.py, baked in at build time ---------- */
(() => {
  const sec = $('#bench'), B = BW.bench;
  if (!sec) return;
  if (!B || !B.local) { sec.hidden = true; return; }
  const T = sec.dataset, bars = $('#bx-bars'), unit = $('#bx-unit'), hint = $('#bx-hint');
  const legend = $('#bx-legend'), note = $('#bx-note'), setBox = $('#bx-set');
  const el = (tag, cls, text) => { const e = d.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const num = (v, digits) => new Intl.NumberFormat(BW.lang, { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(v);
  const ver = id => (B.clients.find(c => c.id === id) || {}).version || '';
  const SUB = { blackwall: 'Zig', happ: 'Xray ' + ver('happ'), xray: 'v2rayN · v2RayTun', singbox: 'Hiddify' };
  const sets = { reality: B.local.protocols.reality, ss2022: B.local.protocols.ss2022, remote: B.remote && B.remote.results };
  if (sets.remote) { $('[data-s="remote"]', setBox).hidden = false; $('[data-m="latency"]').hidden = false; }
  const remote = () => set === 'remote';
  const M = {
    memory: { unit: () => T.uMemory, lower: true, get: r => r.peak_mb, under: r => r.idle_mb,
              text: r => num(r.idle_mb, 1) + ' <em>/ ' + num(r.peak_mb, 1) + '</em>' },
    start: { unit: () => T.uStart, lower: true, get: r => r.start_ms, text: r => num(r.start_ms, 1) },
    cpu: { unit: () => T.uCpu, lower: true, get: r => r.cpu_ms_per_gb, text: r => num(r.cpu_ms_per_gb, 0) },
    speed: { unit: () => remote() ? T.uSpeedRemote : T.uSpeed, lower: false,
             get: r => r.mbps == null ? null : remote() ? r.mbps : r.mbps / 1000,
             text: r => remote() ? num(r.mbps, 1) : num(r.mbps / 1000, 2) },
    latency: { unit: () => T.uLatency, lower: true, get: r => r.handshake_ms, text: r => num(r.handshake_ms, 0) },
    size: { unit: () => T.uSize, lower: true },
  };
  let metric = 'memory', set = 'reality';

  function rows() {
    if (metric === 'size') {
      const a = (B.sizes && B.sizes.app_mb) || {};
      return [['blackwall', 'BLACKWALL', 'Zig'], ['happ', 'Happ', 'Xray · sing-box'], ['v2raytun', 'v2RayTun', 'Xray'], ['hiddify', 'Hiddify', 'sing-box']]
        .filter(([id]) => a[id]).map(([id, name, sub]) => ({ id, name, sub, v: a[id], text: num(a[id], 1) }));
    }
    const res = sets[set] || {}, m = M[metric];
    return B.clients.filter(c => res[c.id] && m.get(res[c.id]) != null).map(c => ({
      id: c.id, name: c.name, sub: SUB[c.id], v: m.get(res[c.id]),
      under: m.under ? m.under(res[c.id]) : null, text: m.text(res[c.id]),
    }));
  }

  function footnote() {
    let date = remote() ? B.remote.date : B.local.date;
    try { date = new Intl.DateTimeFormat(BW.lang, { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(date + 'T00:00:00Z')); } catch (e) {}
    if (!remote()) return T.stand.replace('{machine}', B.machine).replace('{date}', date).replace('{xray}', ver('xray'));
    let country = B.remote.country;
    try { country = new Intl.DisplayNames([BW.lang], { type: 'region' }).of(country) || country; } catch (e) {}
    return T.remoteNote.replace('{date}', date).replace('{country}', country)
      .replace('{protocol}', B.remote.protocol).replace('{rtt}', num(B.remote.rtt_ms, 0));
  }

  function draw() {
    const m = M[metric], rs = rows();
    const max = Math.max(...rs.map(r => r.v), 1e-9);
    const width = v => Math.max(v / max * 100, 0.8).toFixed(2) + '%';
    bars.textContent = '';
    rs.forEach(r => {
      const row = el('div', 'bxr' + (r.id === 'blackwall' ? ' me' : ''));
      const name = el('div', 'bxn');
      name.append(el('b', '', r.name), el('span', '', r.sub || ''));
      const track = el('div', 'bxt'), full = el('i', r.under != null ? 'f' : ''), part = r.under != null ? el('i') : null;
      track.append(full);
      if (part) track.append(part);
      const value = el('div', 'bxv');
      value.innerHTML = r.text;  // formatted numbers only
      row.append(name, track, value);
      bars.append(row);
      const grow = () => { full.style.width = width(r.v); if (part) part.style.width = width(r.under); };
      if (reduce) grow(); else requestAnimationFrame(() => requestAnimationFrame(grow));
    });
    unit.textContent = m.unit();
    hint.textContent = m.lower ? T.lower : T.higher;
    legend.hidden = metric !== 'memory';
    setBox.style.visibility = metric === 'size' ? 'hidden' : '';
    note.textContent = footnote();
  }

  const press = (box, attr, value) => $$('button', box).forEach(b => b.setAttribute('aria-pressed', String(b.dataset[attr] === value)));
  $$('#bx-metric button').forEach(b => b.addEventListener('click', () => {
    metric = b.dataset.m;
    press($('#bx-metric'), 'm', metric);
    draw();
  }));
  $$('button', setBox).forEach(b => b.addEventListener('click', () => {
    set = b.dataset.s;
    if (metric === 'latency' && !remote()) { metric = 'memory'; press($('#bx-metric'), 'm', metric); }
    press(setBox, 's', set);
    draw();
  }));

  // the bars grow the first time they are seen, the headline numbers rise in turn
  const hero = $('.bx-hero', sec);
  if ('IntersectionObserver' in window && !reduce) {
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (!e.isIntersecting) return;
      io.unobserve(e.target);
      if (e.target === hero) hero.classList.add('in'); else draw();
    }), { rootMargin: '0px 0px -12% 0px' });
    io.observe(hero);
    io.observe(bars);
  } else {
    hero.classList.add('in');
    draw();
  }
})();

/* ---------- statistics: what the worker has counted, open to everyone ---------- */
(() => {
  const sec = $('#stats');
  if (!sec || !BW.worker) return;
  const T = sec.dataset, box = $('#chart');
  const el = (tag, cls, text) => { const e = d.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const svg = (tag, attrs) => { const e = d.createElementNS('http://www.w3.org/2000/svg', tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
  let regions = null, dayFmt = null;
  try { regions = new Intl.DisplayNames([BW.lang], { type: 'region' }); } catch (e) {}
  try { dayFmt = new Intl.DateTimeFormat(BW.lang, { day: 'numeric', month: 'short', timeZone: 'UTC' }); } catch (e) {}
  const date = iso => dayFmt ? dayFmt.format(new Date(iso + 'T00:00:00Z')) : iso.slice(5);
  const SYS = { mac: 'macOS', win: 'Windows', linux: 'Linux', ios: 'iOS', android: 'Android', other: '?' };
  function name(dim, key) {
    if (dim === 'os') return SYS[key] || key;
    if (dim === 'country') { try { return (regions && key !== 'XX' && regions.of(key)) || key; } catch (e) { return key; } }
    return key;
  }

  function rows(list, to) {
    to.textContent = '';
    if (!list || !list.length) { to.append(el('p', 'none', T.empty)); return; }
    const max = list[0][1] || 1;
    list.slice(0, 5).forEach(([key, n]) => {
      const row = el('div', 'row');
      row.style.setProperty('--w', (n / max * 100).toFixed(1) + '%');
      row.append(el('span', '', name(to.dataset.dim, key)), el('b', '', nf.format(n)));
      to.append(row);
    });
  }

  // Views and visitors are the same unit, so they share one axis: a bar per day,
  // visitors drawn in front of the views they are part of.
  function chart(daily) {
    box.textContent = '';
    const W = Math.max(280, box.clientWidth - 56), H = 230, L = 38, Tp = 8, B = 26;
    const n = daily.length, iw = W - L, ih = H - Tp - B, band = iw / n, bw = Math.max(2, Math.min(30, band * 0.7));
    const raw = Math.max(1, ...daily.map(x => x.views));
    const pow = Math.pow(10, Math.floor(Math.log10(raw)));
    const top = Math.max(4, Math.ceil(raw / pow * 2) / 2 * pow);
    const base = Tp + ih, y = v => base - v / top * ih, cx = i => L + band * (i + 0.5);
    const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': T.views + ', ' + T.uniques });
    for (let i = 0; i <= 2; i++) {
      const v = top / 2 * i;
      s.append(svg('rect', { x: L, y: Math.round(y(v)), width: iw, height: 1, fill: '#1F1F23' }));
      const t = svg('text', { x: L - 10, y: y(v) + 4, 'text-anchor': 'end' }); t.textContent = nf.format(v); s.append(t);
    }
    [0, Math.floor((n - 1) / 2), n - 1].filter((v, i, a) => a.indexOf(v) === i).forEach(i => {
      const t = svg('text', { x: cx(i), y: H - 6, 'text-anchor': i === 0 && n > 10 ? 'start' : i === n - 1 && n > 10 ? 'end' : 'middle' });
      t.textContent = date(daily[i].day); s.append(t);
    });
    const bar = (i, v, fill) => {
      const h = v / top * ih;
      if (h < 0.5) return;
      const x = cx(i) - bw / 2, r = Math.min(4, bw / 2, h), t = base - h;
      const b = svg('path', { class: 'bar', fill, d: `M${x} ${base}V${t + r}Q${x} ${t} ${x + r} ${t}H${x + bw - r}Q${x + bw} ${t} ${x + bw} ${t + r}V${base}Z` });
      b.style.animationDelay = (reduce ? 0 : i * Math.min(14, 420 / n)) + 'ms';
      s.append(b);
    };
    daily.forEach((p, i) => { bar(i, p.views, '#4A4A54'); bar(i, p.uniques, '#F2F2F3'); });

    const tip = el('div', 'tip'), cols = [];
    daily.forEach((p, i) => {
      const c = svg('rect', { class: 'col', x: L + band * i, y: Tp, width: band, height: ih });
      cols.push(c); s.append(c);
    });
    box.append(s, tip);
    const table = el('table', 'vh'), head = el('tr');
    ['', T.views, T.uniques].forEach(h => head.append(el('th', '', h)));
    table.append(head);
    daily.forEach(p => { const tr = el('tr'); [p.day, p.views, p.uniques].forEach(v => tr.append(el('td', '', v))); table.append(tr); });
    box.append(table);

    let cur = -1;
    const off = () => { if (cur >= 0) cols[cur].classList.remove('on'); cur = -1; tip.classList.remove('show'); };
    s.addEventListener('pointerleave', off);
    s.addEventListener('pointermove', e => {
      const r = s.getBoundingClientRect(), px = (e.clientX - r.left) / r.width * W;
      const i = clamp(Math.floor((px - L) / band), 0, n - 1), p = daily[i];
      if (i === cur) return;
      off(); cur = i; cols[i].classList.add('on');
      tip.textContent = '';
      tip.append(el('b', '', date(p.day)));
      [[T.views, p.views], [T.uniques, p.uniques]].forEach(([k, v]) => { const row = el('div', '', k); row.append(el('i', '', nf.format(v))); tip.append(row); });
      const tx = 28 + cx(i) / W * r.width, full = box.clientWidth;
      tip.style.left = clamp(tx > full / 2 ? tx - tip.offsetWidth - 16 : tx + 16, 8, full - tip.offsetWidth - 8) + 'px';
      tip.classList.add('show');
    });
  }

  let data = null, seen = false, days = 30;
  function draw(first) {
    if (!data || !seen) return;
    [['#sx-views', 'views'], ['#sx-uniques', 'uniques'], ['#sx-dl', 'dl']].forEach(([id, k]) => {
      first ? countUp($(id), data.totals[k]) : ($(id).textContent = nf.format(data.totals[k]));
    });
    chart(data.daily);
    $$('.rows', sec).forEach(to => rows(data.top[to.dataset.dim], to));
  }
  function load(first) {
    fetch(BW.worker + '/stats?days=' + days).then(r => r.ok ? r.json() : null).then(j => {
      if (!j || !j.daily) return;
      data = j;
      sec.hidden = false;
      draw(first);
    }).catch(() => {});
  }
  $$('#period button').forEach(b => b.addEventListener('click', () => {
    days = +b.dataset.d;
    $$('#period button').forEach(o => o.setAttribute('aria-pressed', String(o === b)));
    load(false);
  }));
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(es => { if (es[0].isIntersecting) { seen = true; io.disconnect(); draw(true); } }, { rootMargin: '0px 0px -10% 0px' });
    io.observe(sec);
  } else seen = true;
  let rz = 0, lastW = innerWidth;
  addEventListener('resize', () => { if (innerWidth === lastW) return; lastW = innerWidth; clearTimeout(rz); rz = setTimeout(() => draw(false), 150); });
  if (BW.stats) { data = BW.stats; sec.hidden = false; draw(true); } else load(true);
})();

/* ---------- reveal on scroll ---------- */
if ('IntersectionObserver' in window) {
  const io = new IntersectionObserver(es => es.forEach(e => {
    if (!e.isIntersecting) return;
    e.target.classList.add('in');
    io.unobserve(e.target);
    const n = $('#count-n', e.target);
    if (n) { counted = true; countUp(n, +n.dataset.to || 0); }
  }), { rootMargin: '0px 0px -12% 0px' });
  $$('.rv').forEach(el => io.observe(el));
} else {
  $$('.rv').forEach(el => el.classList.add('in'));
}

/* ---------- navigation ---------- */
const stage = $('#stage');
function onScroll() {
  // the bar folds into the dock once the page has moved, and unfolds only back at the very top
  if (scrollY > 140 && !docked) setDock(true); else if (scrollY < 40 && docked) setDock(false);
  if (stage && !reduce) {
    const vh = innerHeight, top = stage.getBoundingClientRect().top;
    stage.style.setProperty('--p', clamp((vh * 0.96 - top) / (vh * 0.56), 0, 1).toFixed(4));
  }
}
addEventListener('scroll', onScroll, { passive: true });
addEventListener('resize', onScroll);
onScroll();

const ready = () => html.classList.add('ready');
if (d.fonts && d.fonts.ready) Promise.race([d.fonts.ready, new Promise(r => setTimeout(r, 700))]).then(ready);
else ready();

const hero = $('#top');
if (!hero) return;

/* ---------- the window: power button, timer, live graph ---------- */
const demo = $('#demo'), power = $('#power'), label = $('#st-label'), icon = $('#st-icon use');
const timer = $('#timer'), dn = $('#dn'), dnU = $('#dn-u'), up = $('#up'), upU = $('#up-u');
const st = { on: false, since: 0, touched: false, pending: 0 };

function setState(s) {
  demo.dataset.state = s;
  st.on = s === 'on';
  if (st.on) st.since = performance.now();
  label.textContent = label.dataset[s];
  icon.setAttribute('href', s === 'on' ? '#i-shield' : '#i-power');
  power.setAttribute('aria-pressed', String(st.on));
  stage.classList.toggle('on', st.on);
  if (reduce) frame(performance.now());
}
function toggle() {
  clearTimeout(st.pending);
  if (demo.dataset.state === 'off') {
    setState('connecting');
    st.pending = setTimeout(() => setState('on'), 950);
  } else setState('off');
}
power.addEventListener('click', () => { st.touched = true; toggle(); });

function rate(bits) {
  const units = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s'];
  let v = bits, i = 0;
  while (v >= 1000 && i < 3) { v /= 1000; i++; }
  return [i === 0 ? String(Math.round(v)) : v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : String(Math.round(v)), units[i]];
}

const N = 60, TICK = 500;
const down = new Array(N + 1).fill(0), upl = new Array(N + 1).fill(0);
let k = 0, lastTick = 0, peak = 1e6, warm = 0;
function tick() {
  k++;
  warm = st.on ? Math.min(1, warm + 0.25) : 0;
  const v = st.on
    ? Math.max(3e6, 18e6 + 9e6 * Math.sin(k * 0.31) + 6e6 * Math.sin(k * 0.83 + 1) + (Math.random() < 0.12 ? Math.random() * 22e6 : 0) + Math.random() * 4e6) * warm
    : 0;
  const u = st.on ? (v * 0.07 + 0.8e6 + Math.random() * 1e6) * warm : 0;
  down.push(v); down.shift(); upl.push(u); upl.shift();
  const a = rate(v), b = rate(u);
  dn.textContent = a[0]; dnU.textContent = a[1]; up.textContent = b[0]; upU.textContent = b[1];
  if (st.on) {
    const s = Math.floor((performance.now() - st.since) / 1000), p = n => String(n).padStart(2, '0');
    timer.textContent = p(Math.floor(s / 3600)) + ':' + p(Math.floor(s / 60) % 60) + ':' + p(s % 60);
  }
}

const gcv = $('#graph'), g = gcv.getContext('2d');
function drawGraph(phase) {
  // layout sizes, so the tilt of the window does not change the bitmap
  const dpr = Math.min(devicePixelRatio || 1, 2);
  const w = Math.round(gcv.clientWidth * dpr), h = Math.round(gcv.clientHeight * dpr);
  if (!w || !h) return;
  if (gcv.width !== w || gcv.height !== h) { gcv.width = w; gcv.height = h; }
  g.clearRect(0, 0, w, h);
  const u = dpr * demo.clientWidth / (demo.clientWidth < 600 ? 400 : 760);
  peak += (Math.max(1e6, Math.max.apply(null, down) * 1.15) - peak) * 0.08;
  const step = w / (N - 1), base = h - 1.5 * u;
  const path = arr => {
    g.beginPath();
    for (let i = 0; i <= N; i++) {
      const x = (i - phase) * step, y = base - arr[i] / peak * (h - 6 * u);
      i ? g.lineTo(x, y) : g.moveTo(x, y);
    }
  };
  g.lineJoin = 'round';
  path(down);
  g.lineTo(w + step, h); g.lineTo(-step, h); g.closePath();
  g.fillStyle = 'rgba(242,242,243,.07)'; g.fill();
  path(upl); g.strokeStyle = '#6A6A73'; g.lineWidth = 1 * u; g.stroke();
  path(down); g.strokeStyle = '#F2F2F3'; g.lineWidth = 1.6 * u; g.stroke();
}

/* ---------- the wall ---------- */
const cv = $('#wall'), c = cv.getContext('2d');
let W = 0, H = 0, wallY = 0, winTop = 0, cx = 0, gap = 52, lines = [], streams = [], open = 0, t0 = 0;

function offset(el) {
  let x = 0, y = 0;
  while (el && el !== hero) { x += el.offsetLeft; y += el.offsetTop; el = el.offsetParent; }
  return [x, y];
}
function layout() {
  const dpr = Math.min(devicePixelRatio || 1, 2);
  W = hero.clientWidth; H = hero.clientHeight;
  cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
  c.setTransform(dpr, 0, 0, dpr, 0, 0);
  const small = W < 640;
  const pw = offset(power);
  winTop = offset(demo)[1];
  wallY = winTop - (small ? 30 : 44);
  cx = pw[0] + power.offsetWidth / 2;
  gap = small ? 34 : 52;
  const S = small ? 10 : 12;
  lines = [];
  for (let x = cx + S / 2 - Math.ceil(cx / S) * S; x < W; x += S) {
    lines.push({ x: Math.round(x), d: Math.abs(x - cx), edge: clamp(Math.min(x, W - x) / 140, 0, 1) });
  }
  buildStreams(small);
}

/* Streams: curved lines that carry light towards the wall. Those routed through the VPN
   gather into the gap and go on into the window; direct ones bend around it; blocked ones
   end at the wall. With the VPN off the gap is closed and the VPN streams stop there too. */
function curve(x0, y0, x1, y1, side) {
  const c1x = side ? x0 + (x0 < 0 ? 1 : -1) * W * 0.24 : x0, c1y = side ? y0 : y0 + (y1 - y0) * 0.5;
  const c2x = x1, c2y = y1 - Math.min(240, (y1 - y0) * 0.6);
  const pts = [];
  for (let i = 0; i <= 56; i++) {
    const t = i / 56, m = 1 - t;
    pts.push([m * m * m * x0 + 3 * m * m * t * c1x + 3 * m * t * t * c2x + t * t * t * x1,
              m * m * m * y0 + 3 * m * m * t * c1y + 3 * m * t * t * c2y + t * t * t * y1]);
  }
  return pts;
}
function measure(st) {
  st.len = [0];
  for (let i = 1; i < st.pts.length; i++) {
    st.len.push(st.len[i - 1] + Math.hypot(st.pts[i][0] - st.pts[i - 1][0], st.pts[i][1] - st.pts[i - 1][1]));
  }
  st.L = st.len[st.len.length - 1];
}
function pulse(st, first) {
  return { s: first ? Math.random() * st.L : -Math.random() * 420, v: 170 + Math.random() * 210, l: 70 + Math.random() * 130, a: 0.45 + Math.random() * 0.55 };
}
function buildStreams(small) {
  streams = [];
  const n = clamp(Math.round(W / 17), 22, 84), nv = Math.round(n * 0.56), nd = Math.round(n * 0.28);
  const wl = offset(demo)[0], wr = wl + demo.offsetWidth;
  const start = () => {
    const side = !small && Math.random() < 0.34, left = Math.random() < 0.5;
    return side ? [left ? -24 : W + 24, 70 + Math.random() * wallY * 0.55, true] : [Math.random() * W, -24, false];
  };
  // VPN streams keep their order from left to right, so the bundle narrows without crossing
  const vs = Array.from({ length: nv }, start).sort((a, b) => a[0] - b[0] || (a[0] < 0 ? b[1] - a[1] : a[1] - b[1]));
  vs.forEach((p, i) => {
    const ex = cx + (nv > 1 ? i / (nv - 1) - 0.5 : 0) * gap * 1.3;
    const st = { type: 'vpn', pts: curve(p[0], p[1], ex, wallY, p[2]) };
    measure(st); st.wall = st.L;
    st.pts.push([ex, winTop + 8]); measure(st);
    streams.push(st);
  });
  for (let i = 0; i < n - nv; i++) {
    const p = start(), leftward = p[0] < cx, r = Math.random();
    let st;
    if (i < nd) {
      const ex = leftward ? Math.max(6, wl - 28 - r * Math.max(30, wl - 60)) : Math.min(W - 6, wr + 28 + r * Math.max(30, W - wr - 60));
      st = { type: 'direct', pts: curve(p[0], p[1], ex, wallY + (H - wallY) * 0.8, p[2]) };
    } else {
      const reach = Math.max(40, Math.min(W / 2 - gap - 30, 460));
      st = { type: 'block', pts: curve(p[0], p[1], cx + (leftward ? -1 : 1) * (gap + 26 + r * reach), wallY - 2, p[2]) };
    }
    measure(st); st.wall = st.L;
    streams.push(st);
  }
  for (const st of streams) st.pulses = reduce ? [] : [pulse(st, true)];
}
// the point of a stream at a distance from its start, and the index of the next sample
function at(st, dist) {
  const len = st.len;
  let i = 1;
  while (i < len.length - 1 && len[i] < dist) i++;
  const f = clamp((dist - len[i - 1]) / (len[i] - len[i - 1] || 1), 0, 1), p = st.pts[i - 1], q = st.pts[i];
  return [p[0] + (q[0] - p[0]) * f, p[1] + (q[1] - p[1]) * f, i];
}
// the part of a stream between two distances, lit from tail (dark) to head (bright):
// one stroke with one gradient, so the light is a smooth streak and never a row of beads
function lit(st, from, to, rgb, alpha, width) {
  if (to - from < 2) return;
  const a = at(st, from), b = at(st, to);
  let k = alpha * clamp((b[1] + 10) / 190, 0.12, 1);
  if (st.type === 'direct' && b[1] > wallY) k *= clamp(1 - (b[1] - wallY) / ((H - wallY) * 0.8), 0, 1);
  if (k < 0.012) return;
  const gr = c.createLinearGradient(a[0], a[1], b[0], b[1]);
  gr.addColorStop(0, 'rgba(' + rgb + ',0)');
  gr.addColorStop(0.55, 'rgba(' + rgb + ',' + (k * 0.3).toFixed(3) + ')');
  gr.addColorStop(1, 'rgba(' + rgb + ',' + k.toFixed(3) + ')');
  c.strokeStyle = gr; c.lineWidth = width;
  c.beginPath(); c.moveTo(a[0], a[1]);
  for (let i = a[2]; i < b[2]; i++) c.lineTo(st.pts[i][0], st.pts[i][1]);
  c.lineTo(b[0], b[1]);
  c.stroke();
}

function drawWall(now, dt) {
  const t = (now - t0) / 1000;
  open += ((st.on ? 1 : 0) - open) * Math.min(1, dt * 5);
  if (reduce) open = st.on ? 1 : 0;
  c.clearRect(0, 0, W, H);

  if (open > 0.01) {
    const gl = c.createRadialGradient(cx, wallY + 22, 0, cx, wallY + 22, 170);
    gl.addColorStop(0, 'rgba(242,242,243,' + (0.08 * open).toFixed(3) + ')');
    gl.addColorStop(1, 'rgba(242,242,243,0)');
    c.fillStyle = gl; c.fillRect(cx - 170, wallY - 150, 340, 340);
  }

  const body = c.createLinearGradient(0, wallY, 0, H);
  body.addColorStop(0, 'rgba(48,48,54,1)');
  body.addColorStop(0.45, 'rgba(48,48,54,.5)');
  body.addColorStop(1, 'rgba(48,48,54,0)');
  const strip = winTop - wallY + 2;
  for (const l of lines) {
    const grow = reduce ? 1 : ease(clamp((t - Math.min(0.6, l.d / W * 1.3)) / 0.9, 0, 1));
    if (grow <= 0) continue;
    // lines inside the gap sink behind the window, the middle ones first
    const sink = l.d < gap ? ease(clamp(open * 1.6 - l.d / gap * 0.6, 0, 1)) : 0;
    const top = H - (H - wallY) * grow + strip * sink;
    c.globalAlpha = l.edge;
    c.fillStyle = body; c.fillRect(l.x, top, 1, H - top);
    if (!sink) { c.fillStyle = '#6A6A73'; c.fillRect(l.x, top, 1, 5); }
    const near = l.d - gap;
    if (open > 0.01 && near >= 0 && near < 30) {
      c.globalAlpha = open * (near < 12 ? 0.9 : 0.28) * grow;
      c.fillStyle = '#F2F2F3'; c.fillRect(l.x, top, 1, strip);
    }
  }
  c.globalAlpha = 1;
  const shown = reduce ? 1 : ease(clamp((t - 0.5) / 1.2, 0, 1));
  if (shown <= 0) return;
  c.lineCap = 'butt'; c.lineJoin = 'round';

  // the lines themselves, faint
  const fade = rgb => {
    const gr = c.createLinearGradient(0, 0, 0, H);
    gr.addColorStop(0, 'rgba(' + rgb + ',0)');
    gr.addColorStop(clamp(170 / H, 0, 0.5), 'rgba(' + rgb + ',1)');
    gr.addColorStop(clamp(wallY / H, 0.5, 0.99), 'rgba(' + rgb + ',1)');
    gr.addColorStop(1, 'rgba(' + rgb + ',0)');
    return gr;
  };
  const white = fade('242,242,243'), grey = fade('106,106,115');
  c.lineWidth = 1;
  for (const st of streams) {
    const vpn = st.type === 'vpn';
    c.strokeStyle = st.type === 'direct' ? grey : white;
    c.globalAlpha = shown * (vpn ? 0.035 + 0.05 * open : st.type === 'direct' ? 0.1 : 0.03);
    c.beginPath();
    const last = vpn ? st.pts.length - 2 : st.pts.length - 1;
    for (let i = 0; i <= last; i++) i ? c.lineTo(st.pts[i][0], st.pts[i][1]) : c.moveTo(st.pts[0][0], st.pts[0][1]);
    c.stroke();
    if (vpn && open > 0.01) {
      c.globalAlpha = shown * 0.2 * open;
      c.beginPath(); c.moveTo(st.pts[last][0], st.pts[last][1]); c.lineTo(st.pts[last + 1][0], st.pts[last + 1][1]); c.stroke();
    }
  }
  c.globalAlpha = 1;
  if (reduce) return;

  // light running along them
  c.globalCompositeOperation = 'lighter';
  for (const st of streams) {
    const vpn = st.type === 'vpn';
    const limit = vpn && open > 0.5 ? st.L : st.wall;
    const rgb = st.type === 'direct' ? '140,140,150' : '242,242,243';
    for (const p of st.pulses) {
      p.s += p.v * dt * (vpn && p.s > st.wall ? 1.5 : 1);
      if (p.s - p.l > limit) { Object.assign(p, pulse(st)); continue; }
      if (p.s <= 0) continue;
      const head = Math.min(p.s, limit), from = Math.max(0, p.s - p.l);
      const a = p.a * shown * (st.type === 'direct' ? 0.26 : st.type === 'block' ? 0.3 : 0.34 + 0.24 * open);
      lit(st, from, head, rgb, a, 1.2);
      if (p.s >= limit && limit === st.wall) {
        // stopped by the wall: a short mark, red for a blocked stream
        const e = st.pts[vpn ? st.pts.length - 2 : st.pts.length - 1], k = clamp(1 - (p.s - limit) / p.l, 0, 1);
        c.fillStyle = st.type === 'block' ? 'rgba(229,96,79,' + (0.95 * k).toFixed(3) + ')' : 'rgba(242,242,243,' + (0.6 * k).toFixed(3) + ')';
        c.fillRect(e[0] - 5, wallY - 3, 10, 1.5);
      }
    }
  }
  c.globalCompositeOperation = 'source-over';
}

/* ---------- one loop for both canvases; it stops when the first screen is out of view ---------- */
let running = false, visible = true, last = 0;
function frame(now) {
  const dt = Math.min(0.05, (now - last) / 1000 || 0);
  last = now;
  if (now - lastTick >= TICK) { lastTick = now; tick(); }
  drawGraph(reduce ? 0 : clamp((now - lastTick) / TICK, 0, 1));
  drawWall(now, dt);
  if (running) requestAnimationFrame(frame);
}
function sync() {
  const want = visible && !d.hidden && !reduce;
  if (want && !running) { running = true; last = performance.now(); requestAnimationFrame(frame); }
  else if (!want) running = false;
}
if ('IntersectionObserver' in window) new IntersectionObserver(es => { visible = es[0].isIntersecting; sync(); }).observe(hero);
d.addEventListener('visibilitychange', sync);
if ('ResizeObserver' in window) new ResizeObserver(() => { layout(); if (reduce) frame(performance.now()); }).observe(hero);
else addEventListener('resize', layout);

t0 = performance.now();
layout();
if (reduce) { setState('on'); for (let i = 0; i < N; i++) tick(); frame(performance.now()); }
else {
  sync();
  // the window connects by itself once, so the wall is seen opening
  setTimeout(() => { if (!st.touched && demo.dataset.state === 'off') toggle(); }, 2300);
}
})();
