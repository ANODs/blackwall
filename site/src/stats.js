(() => {
'use strict';
const d = document;
const $ = (s, p) => (p || d).querySelector(s);
const $$ = (s, p) => Array.from((p || d).querySelectorAll(s));
const BW = JSON.parse($('#bw').textContent);
const T = $('#stats').dataset;
const nf = new Intl.NumberFormat(BW.lang);
const KEY = 'bw-stats-key';
const el = (tag, cls, text) => { const e = d.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const svg = (tag, attrs) => { const e = d.createElementNS('http://www.w3.org/2000/svg', tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };

$$('[data-lang]').forEach(a => a.addEventListener('click', () => { try { localStorage.setItem('bw-lang', a.dataset.lang); } catch (e) {} }));

const msg = $('#msg'), body = $('#body'), keyForm = $('#key');
const say = text => { msg.textContent = text; msg.hidden = false; body.hidden = true; };
let days = 30;

let regions = null;
try { regions = new Intl.DisplayNames([BW.lang], { type: 'region' }); } catch (e) {}
const NAMES = {
  lang: { en: 'English', ru: 'Русский', zh: '中文' },
  os: { mac: 'macOS', win: 'Windows', linux: 'Linux', ios: 'iOS', android: 'Android', other: '?' },
  dl: { mac: 'macOS', win: 'Windows', linux: 'Linux' },
  device: { desktop: 'Desktop', mobile: 'Mobile' },
};
function name(dim, key) {
  if (dim === 'country') { try { return (regions && key !== 'XX' && regions.of(key)) || key; } catch (e) { return key; } }
  return (NAMES[dim] && NAMES[dim][key]) || key;
}

function rows(box, list) {
  box.textContent = '';
  if (!list || !list.length) { box.append(el('p', 'none', T.empty)); return; }
  const max = list[0][1] || 1;
  list.forEach(([key, n]) => {
    const row = el('div', 'row'), bar = el('div', 'bar'), fill = el('i');
    fill.style.width = (n / max * 100).toFixed(1) + '%';
    bar.append(fill);
    row.append(el('span', '', name(box.dataset.dim, key)), bar, el('b', '', nf.format(n)));
    box.append(row);
  });
}

// Two series of the same unit on one axis: views solid, visitors dashed.
function chart(box, daily) {
  box.textContent = '';
  const W = Math.max(320, box.clientWidth), H = 240, L = 40, R = 12, Tp = 10, B = 26;
  const n = daily.length, iw = W - L - R, ih = H - Tp - B;
  const raw = Math.max(1, ...daily.map(x => x.views));
  const pow = Math.pow(10, Math.floor(Math.log10(raw)));
  const top = Math.max(4, Math.ceil(raw / pow * 2) / 2 * pow);
  const x = i => L + (n > 1 ? i / (n - 1) * iw : iw / 2), y = v => Tp + ih - v / top * ih;
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': T.views + ', ' + T.uniques });

  for (let i = 0; i <= 2; i++) {
    const v = top / 2 * i;
    s.append(svg('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: '#1F1F23', 'stroke-width': 1 }));
    const t = svg('text', { x: L - 10, y: y(v) + 4, 'text-anchor': 'end' }); t.textContent = nf.format(v); s.append(t);
  }
  [0, Math.floor((n - 1) / 2), n - 1].filter((v, i, a) => a.indexOf(v) === i).forEach(i => {
    const t = svg('text', { x: x(i), y: H - 6, 'text-anchor': i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle' });
    t.textContent = daily[i].day.slice(5); s.append(t);
  });
  const line = key => daily.map((p, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(p[key]).toFixed(1)).join('');
  s.append(svg('path', { d: line('uniques'), stroke: '#6A6A73', 'stroke-width': 2, 'stroke-dasharray': '5 4', 'stroke-linejoin': 'round' }));
  s.append(svg('path', { d: line('views'), stroke: '#F2F2F3', 'stroke-width': 2, 'stroke-linejoin': 'round' }));

  const cross = svg('line', { y1: Tp, y2: Tp + ih, stroke: '#303036', 'stroke-width': 1, visibility: 'hidden' });
  const dotU = svg('circle', { r: 4, fill: '#6A6A73', stroke: '#151518', 'stroke-width': 2, visibility: 'hidden' });
  const dotV = svg('circle', { r: 4, fill: '#F2F2F3', stroke: '#151518', 'stroke-width': 2, visibility: 'hidden' });
  s.append(cross, dotU, dotV);
  const tip = el('div', 'tip');
  box.append(s, tip);

  // the same numbers as a table, for readers that cannot use the picture
  const table = el('table', 'vh'), head = el('tr');
  [' ', T.views, T.uniques].forEach(h => head.append(el('th', '', h)));
  table.append(head);
  daily.forEach(p => { const tr = el('tr'); [p.day, p.views, p.uniques].forEach(v => tr.append(el('td', '', v))); table.append(tr); });
  box.append(table);

  const show = on => { [cross, dotU, dotV].forEach(e => e.setAttribute('visibility', on ? 'visible' : 'hidden')); tip.classList.toggle('show', on); };
  s.addEventListener('pointerleave', () => show(false));
  s.addEventListener('pointermove', e => {
    const r = s.getBoundingClientRect(), px = (e.clientX - r.left) / r.width * W;
    const i = Math.min(n - 1, Math.max(0, Math.round((px - L) / (iw || 1) * (n - 1)))), p = daily[i];
    cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i));
    dotV.setAttribute('cx', x(i)); dotV.setAttribute('cy', y(p.views));
    dotU.setAttribute('cx', x(i)); dotU.setAttribute('cy', y(p.uniques));
    tip.textContent = '';
    tip.append(el('b', '', p.day));
    [[T.views, p.views], [T.uniques, p.uniques]].forEach(([k, v]) => { const row = el('div', '', k); row.append(el('i', '', nf.format(v))); tip.append(row); });
    const tx = x(i) / W * r.width;
    tip.style.left = Math.min(r.width - tip.offsetWidth, Math.max(0, tx > r.width / 2 ? tx - tip.offsetWidth - 14 : tx + 14)) + 'px';
    show(true);
  });
}

let data = null;
function draw() {
  if (!data) return;
  msg.hidden = true; keyForm.hidden = true; body.hidden = false;
  $('#t-views').textContent = nf.format(data.totals.views);
  $('#t-uniques').textContent = nf.format(data.totals.uniques);
  $('#t-dl').textContent = nf.format(data.totals.dl);
  chart($('#chart'), data.daily);
  $$('.rows').forEach(box => rows(box, data.top[box.dataset.dim]));
}

async function load() {
  if (!BW.worker) return say(T.off);
  let key = '';
  try { key = localStorage.getItem(KEY) || ''; } catch (e) {}
  try {
    const r = await fetch(BW.worker + '/stats?days=' + days, key ? { headers: { Authorization: 'Bearer ' + key } } : {});
    if (r.status === 401) { msg.hidden = true; body.hidden = true; keyForm.hidden = false; return; }
    if (!r.ok) throw new Error(r.status);
    data = await r.json();
    draw();
  } catch (e) { say(T.err); }
}

keyForm.addEventListener('submit', e => {
  e.preventDefault();
  try { localStorage.setItem(KEY, $('#key-in').value.trim()); } catch (err) {}
  load();
});
$$('#period button').forEach(b => b.addEventListener('click', () => {
  days = +b.dataset.d;
  $$('#period button').forEach(o => o.setAttribute('aria-pressed', String(o === b)));
  load();
}));
let rz = 0;
addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(draw, 150); });
load();
})();
