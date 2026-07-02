// email.js — SPF, DMARC, DKIM, MX, Header Analyzer, Blacklist

async function txtLookup(name) {
  const data = await window.dohQuery(name, 'TXT');
  return (data.Answer || [])
    .filter((a) => a.type === 16)
    .map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
}

// ---------- SPF ----------
// Qualifier labels (window.SPF_QUALIFIERS) and the parser live in core.js.
const SPF_MECHS = {
  ip4: 'Authorize this IPv4 address/range',
  ip6: 'Authorize this IPv6 address/range',
  include: 'Include another domain\'s SPF policy',
  a: 'Authorize the domain\'s A record IPs',
  mx: 'Authorize the domain\'s MX host IPs',
  exists: 'Match if the given domain resolves',
  redirect: 'Replace this policy with another domain\'s',
  exp: 'Explanation string for failures',
  all: 'Match everything else (the catch-all)',
};

async function runSPF(query, panel) {
  const domain = window.hostFromInput(query);
  window.showLoading(panel, 'Looking up SPF…');
  try {
    const records = await txtLookup(domain);
    const spfRecord = records.find((r) => /^v=spf1/i.test(r.trim()));
    if (!spfRecord) { panel.innerHTML = `<div class="summary grey">No SPF record found for ${window.escapeHtml(domain)}.</div>`; return; }
    // parseSpf is the shared, unit-tested parser from core.js.
    const parsed = window.parseSpf(spfRecord);
    const spf = parsed.record;
    const rows = parsed.terms.map((t) => {
      const desc = SPF_MECHS[t.mechanism] || 'Unknown mechanism';
      const plain = t.mechanism === 'all'
        ? `${window.SPF_QUALIFIERS[t.qualifier]} everything not matched above`
        : desc;
      return `<tr><td>${window.escapeHtml(t.raw)}</td><td>${window.escapeHtml(t.value || '—')}</td><td>${window.escapeHtml(plain)} <span class="muted">(${window.SPF_QUALIFIERS[t.qualifier]})</span></td></tr>`;
    }).join('');
    const q = parsed.all || '+';
    const policy = { '-': ['red', 'Strict — unauthorized senders are rejected (-all).'],
      '~': ['yellow', 'Soft — unauthorized senders are marked but usually accepted (~all).'],
      '?': ['grey', 'Neutral — no strong assertion (?all).'],
      '+': ['red', 'Permissive — this authorizes everything (+all). Not recommended.'] }[q] || ['grey', 'No explicit all mechanism.'];
    window.showResult(panel,
      `<div class="summary ${policy[0]}">${window.escapeHtml(policy[1])}</div>` +
      window.card('Raw SPF record', `<pre class="raw">${window.escapeHtml(spf)}</pre>`, spf) +
      window.card('Mechanisms', `<table><thead><tr><th>Mechanism</th><th>Value</th><th>Plain English</th></tr></thead><tbody>${rows}</tbody></table>`));
  } catch (e) {
    window.showError(panel, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

// ---------- DMARC ----------
const DMARC_TAGS = {
  v: 'Protocol version', p: 'Policy for the domain', sp: 'Policy for subdomains',
  pct: 'Percent of mail the policy applies to', rua: 'Aggregate report address',
  ruf: 'Forensic report address', adkim: 'DKIM alignment mode', aspf: 'SPF alignment mode',
  fo: 'Forensic reporting options', ri: 'Aggregate report interval (seconds)',
};
async function runDMARC(query, panel) {
  const domain = window.hostFromInput(query);
  window.showLoading(panel, 'Looking up DMARC…');
  try {
    const records = await txtLookup(`_dmarc.${domain}`);
    const dmarc = records.find((r) => /^v=DMARC1/i.test(r.trim()));
    if (!dmarc) { panel.innerHTML = `<div class="summary grey">No DMARC record found for ${window.escapeHtml(domain)}.</div>`; return; }
    // parseDmarcTags is the shared, unit-tested parser from core.js.
    const tags = window.parseDmarcTags(dmarc);
    const rows = Object.entries(tags).map(([k, v]) =>
      `<tr><td>${window.escapeHtml(k)}</td><td>${window.escapeHtml(v)}</td><td>${window.escapeHtml(DMARC_TAGS[k] || 'Unknown tag')}</td></tr>`
    ).join('');
    const p = (tags.p || 'none').toLowerCase();
    const badge = { reject: 'green', quarantine: 'yellow', none: 'grey' }[p] || 'grey';
    let summary = `Policy: <span class="badge ${badge}">${p.toUpperCase()}</span>`;
    if (tags.pct && tags.pct !== '100') summary += ` &nbsp;·&nbsp; applied to ${window.escapeHtml(tags.pct)}% of mail`;
    if (tags.rua) summary += `<br><span class="muted">Aggregate reports → ${window.escapeHtml(tags.rua)}</span>`;
    const warn = p === 'none' ? `<div class="summary yellow">Monitoring mode only — mail will not be rejected or quarantined.</div>` : '';
    window.showResult(panel,
      warn +
      `<div class="summary ${badge}">${summary}</div>` +
      window.card('Raw DMARC record', `<pre class="raw">${window.escapeHtml(dmarc)}</pre>`, dmarc) +
      window.card('Tags', `<table><thead><tr><th>Tag</th><th>Value</th><th>Plain English</th></tr></thead><tbody>${rows}</tbody></table>`));
  } catch (e) {
    window.showError(panel, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

// ---------- DKIM ----------
async function runDKIM(query, panel) {
  const domain = window.hostFromInput(query);
  if (!panel.dataset.wired) {
    panel.innerHTML = `
      <div class="btn-row">
        <div>
          <label class="field-label">Selector</label>
          <input class="text-input" id="dkim-selector" placeholder="google, selector1, default, mail" />
        </div>
        <button class="btn primary" id="dkim-go" style="align-self:flex-end">Look up</button>
      </div>
      <div class="result" id="dkim-result"><div class="note">Enter a DKIM selector, then Look up.</div></div>`;
    const go = () => doDKIM(domain, panel);
    panel.querySelector('#dkim-go').addEventListener('click', go);
    panel.querySelector('#dkim-selector').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    panel.dataset.wired = '1';
  }
}
async function doDKIM(domain, panel) {
  const selector = panel.querySelector('#dkim-selector').value.trim();
  const out = panel.querySelector('#dkim-result');
  if (!selector) { window.showError(out, 'Enter a selector to look up.'); return; }
  window.showLoading(out, 'Looking up DKIM…');
  try {
    const name = `${selector}._domainkey.${domain}`;
    const records = await txtLookup(name);
    const dkim = records.find((r) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(r)) || records[0];
    if (!dkim) { out.innerHTML = `<div class="summary grey">No DKIM record found at ${window.escapeHtml(name)}.</div>`; return; }
    const tags = {};
    dkim.split(';').forEach((seg) => {
      const [k, ...v] = seg.trim().split('=');
      if (k) tags[k.trim().toLowerCase()] = (v.join('=') || '').trim();
    });
    const pubLen = tags.p ? Math.round(tags.p.replace(/[^A-Za-z0-9+/=]/g, '').length * 6 / 8 * 8) : 0;
    const bits = tags.p ? `~${Math.round(tags.p.length * 6 / 8)} bytes` : '—';
    const rows = [
      ['v', tags.v || 'DKIM1', 'Version'],
      ['k', tags.k || 'rsa', 'Key type'],
      ['t', tags.t || '—', tags.t ? 'Flags' : 'No flags'],
      ['p', tags.p ? `${window.escapeHtml(tags.p.slice(0, 32))}… (${bits})` : '(empty — key revoked)', 'Public key'],
    ].map(([k, v, d]) => `<tr><td>${k}</td><td>${v}</td><td>${window.escapeHtml(d)}</td></tr>`).join('');
    const warn = /(^|;|,|\s)t=y/i.test('t=' + (tags.t || ''))
      ? `<div class="summary yellow">Testing mode (t=y) — DKIM failures won't affect delivery.</div>` : '';
    out.innerHTML =
      warn +
      window.card(`Raw DKIM record — ${selector}`, `<pre class="raw">${window.escapeHtml(dkim)}</pre>`, dkim) +
      window.card('Parsed', `<table><thead><tr><th>Tag</th><th>Value</th><th>Meaning</th></tr></thead><tbody>${rows}</tbody></table>`);
  } catch (e) {
    window.showError(out, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

// ---------- MX ----------
async function runMX(query, panel) {
  const domain = window.hostFromInput(query);
  window.showLoading(panel, 'Looking up MX…');
  try {
    const data = await window.dohQuery(domain, 'MX');
    const mx = (data.Answer || []).filter((a) => a.type === 15).map((a) => {
      const [prio, host] = a.data.split(/\s+/);
      return { prio: Number(prio), host: host.replace(/\.$/, '') };
    }).sort((a, b) => a.prio - b.prio);
    if (!mx.length) { panel.innerHTML = `<div class="summary grey">No MX records found for ${window.escapeHtml(domain)}.</div>`; return; }

    const rows = await Promise.all(mx.map(async (m) => {
      let ips = [];
      try { const a = await window.dohQuery(m.host, 'A'); ips = (a.Answer || []).filter((x) => x.type === 1).map((x) => x.data); } catch (e) { /* ignore */ }
      const ptrs = await Promise.all(ips.map(async (ip) => {
        try {
          const rev = ip.split('.').reverse().join('.') + '.in-addr.arpa';
          const p = await window.dohQuery(rev, 'PTR');
          const ptr = (p.Answer || []).filter((x) => x.type === 12).map((x) => x.data.replace(/\.$/, ''))[0] || '';
          return { ip, ptr };
        } catch (e) { return { ip, ptr: '' }; }
      }));
      return { ...m, ips, ptrs };
    }));

    const body = rows.map((m) => {
      const ipCell = m.ips.length ? m.ips.map((x) => window.escapeHtml(x)).join('<br>') : '<span class="muted">—</span>';
      const ptrCell = m.ptrs.length ? m.ptrs.map((p) => window.escapeHtml(p.ptr || '—')).join('<br>') : '<span class="muted">—</span>';
      // PTR "match" = PTR hostname points back toward the MX host domain
      const match = m.ptrs.length && m.ptrs.every((p) => p.ptr) ? '<span class="ok">✓</span>' : '<span class="warn">✗</span>';
      return `<tr><td>${m.prio}</td><td>${window.escapeHtml(m.host)}</td><td>${ipCell}</td><td>${ptrCell}</td><td>${match}</td></tr>`;
    }).join('');
    panel.innerHTML = window.card('MX records', `<table><thead><tr><th>Priority</th><th>MX Host</th><th>IP(s)</th><th>PTR</th><th>PTR set</th></tr></thead><tbody>${body}</tbody></table>`);
  } catch (e) {
    window.showError(panel, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

// ---------- Header Analyzer ----------
function runHeaders(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Parsed entirely in your browser. Pasted headers are never sent anywhere.</div>
    <textarea class="mono" id="hdr-input" placeholder="Paste raw email headers here…"></textarea>
    <div class="btn-row"><button class="btn primary" id="hdr-go">Analyze</button></div>
    <div class="result" id="hdr-result"></div>`;
  panel.querySelector('#hdr-go').addEventListener('click', () => analyzeHeaders(panel));
  panel.dataset.wired = '1';
}
function analyzeHeaders(panel) {
  const raw = panel.querySelector('#hdr-input').value;
  const out = panel.querySelector('#hdr-result');
  if (!raw.trim()) { window.showError(out, 'Paste some headers first.'); return; }

  // Unfold headers (continuation lines start with whitespace)
  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
  const lines = unfolded.split(/\r?\n/);
  const headers = [];
  lines.forEach((line) => {
    const m = /^([!-9;-~]+):\s?(.*)$/.exec(line);
    if (m) headers.push({ key: m[1], value: m[2] });
  });
  const get = (k) => headers.filter((h) => h.key.toLowerCase() === k.toLowerCase()).map((h) => h.value);

  // Received chain (top = most recent). Reverse for chronological order.
  const received = get('Received').reverse();
  let prevTime = null;
  const hops = received.map((r, i) => {
    const dm = /;\s*(.+)$/.exec(r);
    const time = dm ? new Date(dm[1].trim()) : null;
    let delay = '';
    if (time && prevTime && !isNaN(time) && !isNaN(prevTime)) {
      const s = Math.round((time - prevTime) / 1000);
      delay = s >= 0 ? `+${s}s` : `${s}s`;
    }
    if (time && !isNaN(time)) prevTime = time;
    const from = /from\s+(\S+)/i.exec(r);
    const by = /by\s+(\S+)/i.exec(r);
    return { i: i + 1, from: from ? from[1] : '?', by: by ? by[1] : '?', time: (dm ? dm[1].trim() : ''), delay };
  });

  const chainHtml = hops.map((h) =>
    `<li><strong>${h.i}.</strong> ${window.escapeHtml(h.from)} → ${window.escapeHtml(h.by)} <span class="muted">${window.escapeHtml(h.time)} ${h.delay ? '(' + h.delay + ')' : ''}</span></li>`
  ).join('');

  // Authentication results
  const authRaw = get('Authentication-Results').join(' ') + ' ' + get('ARC-Authentication-Results').join(' ');
  const authFor = (mech) => {
    const m = new RegExp(`${mech}=(\\w+)`, 'i').exec(authRaw);
    if (!m) return { v: 'none', cls: 'grey' };
    const v = m[1].toLowerCase();
    const cls = v === 'pass' ? 'ok' : (v === 'fail' || v === 'softfail' ? 'err' : 'muted');
    return { v, cls };
  };
  const spf = authFor('spf'), dkim = authFor('dkim'), dmarc = authFor('dmarc');
  const authHtml = `<table><tbody>
    <tr><td>SPF</td><td class="${spf.cls}">${spf.v}</td></tr>
    <tr><td>DKIM</td><td class="${dkim.cls}">${dkim.v}</td></tr>
    <tr><td>DMARC</td><td class="${dmarc.cls}">${dmarc.v}</td></tr></tbody></table>`;

  const meta = [
    ['From', get('From')[0]], ['To', get('To')[0]], ['Subject', get('Subject')[0]],
    ['Date', get('Date')[0]], ['Message-ID', get('Message-ID')[0]],
    ['X-Spam-Status', get('X-Spam-Status')[0]], ['X-Spam-Score', get('X-Spam-Score')[0]],
  ].filter(([, v]) => v).map(([k, v]) => `<tr><td>${k}</td><td>${window.escapeHtml(v)}</td></tr>`).join('');

  out.innerHTML =
    window.card('Authentication results', authHtml) +
    window.card('Message details', `<table><tbody>${meta}</tbody></table>`) +
    window.card(`Routing path (${hops.length} hops, oldest first)`, chainHtml ? `<ul class="chain">${chainHtml}</ul>` : '<div class="muted">No Received headers found.</div>');
}

// ---------- Blacklist (RBL) ----------
async function runRBL(query, panel) {
  window.showLoading(panel, 'Resolving target…');
  try {
    const ip = await window.resolveToIP(window.hostFromInput(query));
    window.showLoading(panel, `Checking ${ip} against blacklists…`);
    const res = await fetch(`/api/rbl?ip=${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error(`RBL check failed (${res.status})`);
    const data = await res.json();
    const results = data.results || data;
    const listed = results.filter((r) => r.listed);
    const summaryCls = listed.length ? 'red' : 'green';
    const summary = `<div class="summary ${summaryCls}">Listed on ${listed.length} of ${results.length} checked blacklists${listed.length ? '.' : ' — clean.'}</div>`;
    const rows = results.map((r) =>
      `<tr><td>${window.escapeHtml(r.list)}</td><td>${r.listed ? '<span class="badge red">LISTED</span>' : '<span class="badge green">clean</span>'}</td><td>${window.escapeHtml(r.response || '—')}</td></tr>`
    ).join('');
    panel.innerHTML = summary + window.card(`Blacklist check — ${ip}`, `<table><thead><tr><th>Blacklist</th><th>Status</th><th>Response</th></tr></thead><tbody>${rows}</tbody></table>`);
  } catch (e) {
    window.showError(panel, e.message || 'Blacklist check failed.');
  }
}

window.registerRunner('email', 'spf', runSPF);
window.registerRunner('email', 'dmarc', runDMARC);
window.registerRunner('email', 'dkim', runDKIM);
window.registerRunner('email', 'mx', runMX);
window.registerRunner('email', 'headers', runHeaders);
window.registerRunner('email', 'rbl', runRBL);
