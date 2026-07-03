// tools.js — client-side sysadmin utilities (Hash, Password/UUID, Epoch, Cron,
// Chmod, JSON). All run entirely in the browser; nothing is sent anywhere.

function wire(root) { window.wireCopyButtons(root); }
function copyBtn(text) { return `<button class="copy-btn" data-copy="${window.escapeHtml(text)}">copy</button>`; }

// ================= Hash =================
async function shaHex(algo, str) {
  const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function runHash(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Hashed entirely in your browser.</div>
    <label class="field-label">Input</label>
    <textarea class="mono" id="hash-in" placeholder="Type or paste text to hash…"></textarea>
    <div class="result" id="hash-out"></div>`;
  const inp = panel.querySelector('#hash-in');
  const out = panel.querySelector('#hash-out');
  const update = async () => {
    const v = inp.value;
    if (!v) { out.innerHTML = ''; return; }
    const [s1, s256, s384, s512] = await Promise.all([
      shaHex('SHA-1', v), shaHex('SHA-256', v), shaHex('SHA-384', v), shaHex('SHA-512', v),
    ]);
    const rows = [
      ['MD5', window.md5(v)], ['SHA-1', s1], ['SHA-256', s256], ['SHA-384', s384], ['SHA-512', s512],
    ].map(([k, h]) => `<tr><td>${k}</td><td class="data-cell"><span class="data-val">${h}</span><button class="copy-cell" data-copy="${h}" title="Copy">⧉</button></td></tr>`).join('');
    out.innerHTML = window.card('Hashes', `<table><tbody>${rows}</tbody></table>`);
    wire(out);
  };
  inp.addEventListener('input', update);
  panel.dataset.wired = '1';
}

// ================= Password / UUID =================
function randomInt(max) {
  const a = new Uint32Array(1);
  const limit = Math.floor(0xffffffff / max) * max;
  let x;
  do { crypto.getRandomValues(a); x = a[0]; } while (x >= limit);
  return x % max;
}
function runGen(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Generated in your browser with a cryptographic RNG. Never transmitted.</div>
    <div class="btn-row">
      <label class="field-label" style="margin:0">Length <input type="number" id="pw-len" class="text-input" value="20" min="4" max="128" style="width:5rem"></label>
      <label><input type="checkbox" id="pw-upper" checked> A-Z</label>
      <label><input type="checkbox" id="pw-lower" checked> a-z</label>
      <label><input type="checkbox" id="pw-digit" checked> 0-9</label>
      <label><input type="checkbox" id="pw-sym" checked> symbols</label>
      <button class="btn primary" id="pw-go">Generate</button>
    </div>
    <div class="result" id="pw-out"></div>
    <div class="btn-row" style="margin-top:1rem"><button class="btn" id="uuid-go">Generate UUID v4</button></div>
    <div class="result" id="uuid-out"></div>`;
  const out = panel.querySelector('#pw-out');
  const gen = () => {
    let pool = '';
    if (panel.querySelector('#pw-upper').checked) pool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (panel.querySelector('#pw-lower').checked) pool += 'abcdefghijklmnopqrstuvwxyz';
    if (panel.querySelector('#pw-digit').checked) pool += '0123456789';
    if (panel.querySelector('#pw-sym').checked) pool += '!@#$%^&*()-_=+[]{};:,.<>?';
    const len = Math.max(4, Math.min(128, Number(panel.querySelector('#pw-len').value) || 20));
    if (!pool) { window.showError(out, 'Pick at least one character set.'); return; }
    let pw = '';
    for (let i = 0; i < len; i++) pw += pool[randomInt(pool.length)];
    const bits = window.passwordEntropyBits(len, pool.length);
    const strength = bits >= 100 ? 'green' : bits >= 60 ? 'yellow' : 'red';
    out.innerHTML = window.card('Password',
      `<pre class="raw">${window.escapeHtml(pw)}</pre><div class="summary ${strength}">~${bits} bits of entropy</div>`, pw);
    wire(out);
  };
  panel.querySelector('#pw-go').addEventListener('click', gen);
  panel.querySelector('#uuid-go').addEventListener('click', () => {
    const u = crypto.randomUUID();
    const uo = panel.querySelector('#uuid-out');
    uo.innerHTML = window.card('UUID v4', `<pre class="raw">${u}</pre>`, u);
    wire(uo);
  });
  gen();
  panel.dataset.wired = '1';
}

// ================= Epoch =================
function runEpoch(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Converted in your browser.</div>
    <div id="epoch-now" class="note"></div>
    <div class="btn-row">
      <input class="text-input" id="epoch-in" placeholder="Unix timestamp (1700000000) or a date (2024-01-31 14:00)" style="flex:1;min-width:18rem">
      <button class="btn primary" id="epoch-go">Convert</button>
    </div>
    <div class="result" id="epoch-out"></div>`;
  const nowEl = panel.querySelector('#epoch-now');
  const tick = () => { nowEl.textContent = `Current Unix time: ${Math.floor(Date.now() / 1000)}`; };
  tick(); panel._epochTimer = setInterval(tick, 1000);
  const out = panel.querySelector('#epoch-out');
  const conv = () => {
    const v = panel.querySelector('#epoch-in').value.trim();
    if (!v) { out.innerHTML = ''; return; }
    let parts;
    if (/^-?\d+$/.test(v)) parts = window.epochToParts(v);
    else { const d = new Date(v); parts = isNaN(d.getTime()) ? null : window.epochToParts(d.getTime()); }
    if (!parts) { window.showError(out, 'Enter a Unix timestamp or a parseable date.'); return; }
    const d = new Date(parts.ms);
    const rows = [
      ['Unix (seconds)', String(parts.seconds)],
      ['Unix (millis)', String(parts.ms)],
      ['ISO 8601 (UTC)', parts.iso],
      ['UTC', parts.utc],
      ['Local', d.toString()],
    ].map(([k, val]) => `<tr><td>${k}</td><td class="data-cell"><span class="data-val">${window.escapeHtml(val)}</span><button class="copy-cell" data-copy="${window.escapeHtml(val)}" title="Copy">⧉</button></td></tr>`).join('');
    out.innerHTML = window.card('Conversion', `<table><tbody>${rows}</tbody></table>`);
    wire(out);
  };
  panel.querySelector('#epoch-go').addEventListener('click', conv);
  panel.querySelector('#epoch-in').addEventListener('keydown', (e) => { if (e.key === 'Enter') conv(); });
  panel.dataset.wired = '1';
}

// ================= Cron =================
function runCron(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Parsed in your browser.</div>
    <div class="btn-row">
      <input class="text-input" id="cron-in" placeholder="*/15 2 * * 1-5" style="flex:1;min-width:16rem">
      <button class="btn primary" id="cron-go">Explain</button>
    </div>
    <div class="note">Fields: minute hour day-of-month month day-of-week. Times shown in UTC and your local zone.</div>
    <div class="result" id="cron-out"></div>`;
  const out = panel.querySelector('#cron-out');
  const explain = () => {
    const expr = panel.querySelector('#cron-in').value.trim();
    if (!expr) { out.innerHTML = ''; return; }
    const desc = window.describeCron(expr);
    const cron = window.parseCron(expr);
    if (!desc || !cron) { window.showError(out, 'Invalid cron expression (expects 5 fields).'); return; }
    const runs = window.nextCronRuns(cron, new Date(), 5);
    const runRows = runs.map((r) => `<tr><td>${window.escapeHtml(r.toISOString().replace('.000', ''))}</td><td>${window.escapeHtml(r.toLocaleString())}</td></tr>`).join('')
      || '<tr><td colspan="2" class="muted">No upcoming runs found in the next ~5 years.</td></tr>';
    out.innerHTML =
      window.card('Meaning', `<div class="summary grey">Runs at ${window.escapeHtml(desc)}.</div>`) +
      window.card('Next 5 runs', `<table><thead><tr><th>UTC</th><th>Local</th></tr></thead><tbody>${runRows}</tbody></table>`);
    wire(out);
  };
  panel.querySelector('#cron-go').addEventListener('click', explain);
  panel.querySelector('#cron-in').addEventListener('keydown', (e) => { if (e.key === 'Enter') explain(); });
  panel.dataset.wired = '1';
}

// ================= Chmod =================
function runChmod(query, panel) {
  if (panel.dataset.wired) return;
  const who = ['Owner', 'Group', 'Other'];
  const perm = ['r', 'w', 'x'];
  const grid = who.map((w, i) => `<tr><td>${w}</td>` +
    perm.map((p) => `<td style="text-align:center"><input type="checkbox" data-i="${i}" data-p="${p}"></td>`).join('') + '</tr>').join('');
  panel.innerHTML = `
    <div class="privacy-note">Calculated in your browser.</div>
    <div class="btn-row">
      <label class="field-label" style="margin:0">Octal <input class="text-input" id="chmod-oct" placeholder="755" style="width:6rem"></label>
      <label class="field-label" style="margin:0">Symbolic <input class="text-input" id="chmod-sym" placeholder="rwxr-xr-x" style="width:9rem"></label>
    </div>
    <table style="max-width:20rem"><thead><tr><th></th><th>read</th><th>write</th><th>exec</th></tr></thead><tbody>${grid}</tbody></table>
    <div class="result" id="chmod-out" style="margin-top:0.75rem"></div>`;
  const octEl = panel.querySelector('#chmod-oct');
  const symEl = panel.querySelector('#chmod-sym');
  const boxes = [...panel.querySelectorAll('input[type=checkbox]')];
  const out = panel.querySelector('#chmod-out');

  const render = (octal) => {
    const info = window.chmodDescribe(octal);
    if (!info) { out.innerHTML = ''; return; }
    out.innerHTML = window.card(`${octal} — ${info.symbolic}`,
      `<div>${info.lines.map((l) => window.escapeHtml(l)).join('<br>')}</div>`, `chmod ${octal}`);
    wire(out);
  };
  const fromBoxes = () => {
    let oct = '';
    for (let i = 0; i < 3; i++) {
      const g = boxes.filter((b) => Number(b.dataset.i) === i);
      oct += (g[0].checked ? 4 : 0) + (g[1].checked ? 2 : 0) + (g[2].checked ? 1 : 0);
    }
    octEl.value = oct; symEl.value = window.chmodToSymbolic(oct); render(oct);
  };
  const setBoxes = (sym) => {
    for (let i = 0; i < 3; i++) {
      const g = sym.slice(i * 3, i * 3 + 3);
      const bs = boxes.filter((b) => Number(b.dataset.i) === i);
      bs[0].checked = g[0] === 'r'; bs[1].checked = g[1] === 'w'; bs[2].checked = 'xsStT'.includes(g[2]);
    }
  };
  boxes.forEach((b) => b.addEventListener('change', fromBoxes));
  octEl.addEventListener('input', () => {
    const sym = window.chmodToSymbolic(octEl.value.trim());
    if (sym) { symEl.value = sym; setBoxes(sym); render(octEl.value.trim().slice(-3).padStart(3, '0')); }
  });
  symEl.addEventListener('input', () => {
    const oct = window.chmodToOctal(symEl.value.trim());
    if (oct) { octEl.value = oct; setBoxes(window.chmodToSymbolic(oct)); render(oct); }
  });
  octEl.value = '644'; symEl.value = 'rw-r--r--'; setBoxes('rw-r--r--'); render('644');
  panel.dataset.wired = '1';
}

// ================= JSON formatter =================
function runJson(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Formatted in your browser.</div>
    <textarea class="mono" id="json-in" placeholder='{"paste":"JSON here"}'></textarea>
    <div class="btn-row">
      <button class="btn primary" id="json-fmt">Format</button>
      <button class="btn" id="json-min">Minify</button>
      <span id="json-msg" class="muted"></span>
    </div>
    <div class="result" id="json-out"></div>`;
  const inp = panel.querySelector('#json-in');
  const msg = panel.querySelector('#json-msg');
  const out = panel.querySelector('#json-out');
  const run = (indent) => {
    const raw = inp.value.trim();
    if (!raw) { out.innerHTML = ''; msg.textContent = ''; return; }
    let obj;
    try { obj = JSON.parse(raw); } catch (e) { msg.innerHTML = `<span class="err">Invalid JSON: ${window.escapeHtml(e.message)}</span>`; out.innerHTML = ''; return; }
    msg.innerHTML = '<span class="ok">Valid JSON ✓</span>';
    const formatted = JSON.stringify(obj, null, indent);
    out.innerHTML = window.card('Output', `<pre class="raw">${window.escapeHtml(formatted)}</pre>`, formatted);
    wire(out);
  };
  panel.querySelector('#json-fmt').addEventListener('click', () => run(2));
  panel.querySelector('#json-min').addEventListener('click', () => run(0));
  panel.dataset.wired = '1';
}

window.registerRunner('utils', 'hash', runHash);
window.registerRunner('utils', 'gen', runGen);
window.registerRunner('utils', 'epoch', runEpoch);
window.registerRunner('utils', 'cron', runCron);
window.registerRunner('utils', 'chmod', runChmod);
window.registerRunner('utils', 'json', runJson);
