// overview.js — one input, everything checked.
//
// The same lookups the DNS / Email / Web / Whois tabs do individually, fired
// together and condensed into a scored report. Everything here is orchestration:
// what a finding *means* and what it costs lives in core.js's domainReport(),
// which is pure and unit-tested.
//
// Cost per report: ~25 DNS queries (issued straight from the browser via DoH —
// free, and only proxied through /api/dns when the network blocks direct DoH)
// plus four Pages Functions calls (/api/rbl, /api/headers, /api/tls,
// /api/whois) and one ipwho.is lookup. The category subtabs are filters over
// that one collection — switching DNS -> Email starts no new lookups.

const OV_TYPES = ['A', 'AAAA', 'NS', 'CNAME', 'SOA', 'DS', 'DNSKEY', 'CAA', 'TXT', 'MX'];
const OV_TYPE_NUM = {
  A: 1, AAAA: 28, NS: 2, CNAME: 5, SOA: 6, DS: 43, DNSKEY: 48, CAA: 257, TXT: 16, MX: 15, PTR: 12,
};
const OV_PROP_RESOLVERS = ['cloudflare', 'google', 'dnssb'];

// Subtab -> the report section it shows (null = all of them). Keeping this in
// the URL (?tab=overview&sub=email&q=…) makes a single category shareable.
const OV_SECTION_BY_SUB = { all: null, dns: 'DNS', email: 'Email', web: 'Web', reg: 'Registration' };
const OV_SECTION_ORDER = ['DNS', 'Email', 'Web', 'Registration'];

// The one collected report, shared by every subtab panel. Bumped (with a new
// run token) when the domain changes, so a slow response from a superseded run
// can't paint over the report the user is now looking at.
let ovState = null;
let overviewRun = 0;

// One DoH query, reduced to what the report needs. Never throws: a failed
// lookup comes back { ok:false } and is recorded as "unknown", not "failed".
async function ovDns(name, type) {
  try {
    const data = await window.dohQuery(name, type);
    const want = OV_TYPE_NUM[type];
    const rows = (data.Answer || []).filter((r) => want === undefined || Number(r.type) === want);
    const value = type === 'TXT'
      ? rows.map((r) => (typeof unquoteTxt === 'function' ? unquoteTxt(String(r.data)) : String(r.data).replace(/^"|"$/g, '')))
      : rows.map((r) => String(r.data).trim().replace(/\.$/, ''));
    return { ok: true, ad: data.AD === true, nx: data.Status === 3, value, ttl: rows.length ? rows[0].TTL : null };
  } catch (e) {
    return { ok: false, ad: false, nx: false, value: [], ttl: null };
  }
}

// IP -> PTR (for an MX hostname, via its address first).
async function ovPtr(ipOrHost) {
  let ip = ipOrHost;
  if (!window.isIP(ip)) {
    const a = await ovDns(ip, 'A');
    ip = (a.value || []).find((x) => window.isIPv4(x));
    if (!ip) return '';
  }
  const p = await ovDns(reverseInAddr(ip), 'PTR');
  return p.value[0] || '';
}

function ovMx(value) {
  // "10 mail.example.com." -> {prio:10, host:'mail.example.com'}; the RFC 7505
  // null MX ("0 .") -> {prio:0, host:''}, which the report reads as "no mail".
  const parts = String(value || '').trim().split(/\s+/);
  const prio = Number(parts[0]);
  const host = (parts[1] || '').replace(/\.$/, '');
  return { prio: Number.isFinite(prio) ? prio : 0, host: host === '.' ? '' : host };
}

// Fetch the target over HTTPS; if that's dead, try plain HTTP so the report can
// say "it only serves HTTP" instead of "fetch failed".
async function ovHttp(host) {
  let httpsErr = '';
  try {
    return { chain: await fetchChain(`https://${host}`) };
  } catch (e) {
    httpsErr = (e && e.message) || 'HTTPS request failed';
  }
  try {
    return { chain: await fetchChain(`http://${host}`), httpOnly: true, httpsErr };
  } catch (e) {
    return { error: `${httpsErr}; plain HTTP failed too` };
  }
}

async function ovJson(path, failMsg) {
  try {
    const res = await fetch(path);
    const data = await res.json().catch(() => null);
    if (!res.ok) return { error: (data && data.error) || `${failMsg} (${res.status})` };
    return data || { error: failMsg };
  } catch (e) {
    return { error: (e && e.message) || failMsg };
  }
}

// ---------- rendering ----------

function rowsHtml(items, e) {
  const mark = { ok: 'green', warn: 'yellow', bad: 'red', info: 'grey', pending: 'grey' };
  const word = { ok: 'PASS', warn: 'WARN', bad: 'FAIL', info: 'INFO', pending: '…' };
  return items.map((i) =>
    `<tr${i.status === 'bad' ? ' class="fail"' : ''}><td class="st"><span class="badge ${mark[i.status]}">${word[i.status]}</span></td>` +
    `<td class="lbl">${e(i.label)}</td>` +
    `<td class="dt">${i.status === 'pending' ? '<span class="muted">checking\u2026</span>' : e(i.detail)}</td>` +
    `<td class="ln">${i.link && i.status !== 'pending' ? `<button class="row-link" data-jump="${e(i.link)}">detail \u2192</button>` : ''}</td></tr>`
  ).join('');
}

function attentionHtml(items, e) {
  return window.card(`Needs attention (${items.length})`, '<ul class="fixes">' + items.map((i) =>
    `<li><span class="badge ${i.status === 'bad' ? 'red' : 'yellow'}">${i.status === 'bad' ? 'FAIL' : 'WARN'}</span> ` +
    `<strong>${e(i.label)}</strong> — ${e(i.detail)}` +
    (i.link ? ` <button class="row-link" data-jump="${e(i.link)}">open ${e(i.link.replace(':', ' > '))}</button>` : '') +
    '</li>').join('') + '</ul>');
}

function reportHtml(raw, sub) {
  const rep = window.domainReport(raw);
  const e = window.escapeHtml;
  const section = Object.prototype.hasOwnProperty.call(OV_SECTION_BY_SUB, sub) ? OV_SECTION_BY_SUB[sub] : null;

  if (!rep.judged && !rep.items.some((i) => i.status === 'pending')) {
    return '<div class="summary red">Nothing could be checked. Every lookup failed — this network may be ' +
      'blocking DNS-over-HTTPS and the site&#39;s own resolver endpoints.</div>';
  }

  const problems = rep.items.filter((i) => i.status === 'bad' || i.status === 'warn');
  const shown = section ? rep.items.filter((i) => i.section === section) : rep.items;
  const shownProblems = shown.filter((i) => i.status === 'bad' || i.status === 'warn');
  const elsewhere = problems.length - shownProblems.length;

  const head =
    `<div class="report-head"><div class="grade ${rep.grade}">${rep.grade}</div><div>` +
    `<div class="report-score">${rep.score}<span>/100</span></div>` +
    `<div class="muted">${e(raw.domain)} · ${rep.counts.ok} pass · ${rep.counts.warn} warn · ${rep.counts.bad} fail` +
    (rep.counts.pending ? ` · ${rep.counts.pending} still running` : '') + '</div></div></div>';

  const intro = section ? '' :
    '<div class="note">One pass over the domain: DNS and DNSSEC, mail authentication, the web server, and ' +
    'the registration. Pick a category above to see fewer rows; every row links to the tool that explains it.</div>';

  let attention = '';
  if (shownProblems.length) attention = attentionHtml(shownProblems, e);
  else if (!section) attention = '<div class="summary green">✓ Nothing failed and nothing is warning — see the detail below.</div>';
  else if (problems.length) attention = `<div class="summary grey">✓ Nothing to fix in ${e(section)} — ${problems.length} to look at elsewhere${elsewhere === problems.length ? '' : ' (see the other categories above)'}.` + '</div>';
  else attention = `<div class="summary green">✓ Nothing to fix in ${e(section)}.</div>`;

  let bodies = '';
  if (section) {
    bodies = shown.length ? window.card(section, `<table class="report-table"><tbody>${rowsHtml(shown, e)}</tbody></table>`) : '';
  } else {
    bodies = OV_SECTION_ORDER.map((name) => {
      const rows = rep.items.filter((i) => i.section === name);
      return rows.length ? window.card(name, `<table class="report-table"><tbody>${rowsHtml(rows, e)}</tbody></table>`) : '';
    }).join('');
  }

  let appendix = '';
  if (!section) {
    const records = raw.records;
    const rawBits = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'CAA', 'SOA'].filter((t) => (records[t] || []).length)
      .map((t) => `<tr><td>${t}</td><td>${records[t].map((v) => e(typeof v === 'object' ? `${v.prio} ${v.host}` : v)).join('<br>')}</td></tr>`)
      .join('');
    if (rawBits) appendix = window.card('Records seen', `<table class="headers-table"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>${rawBits}</tbody></table>`);
  }

  return intro + head + attention + bodies + appendix +
    '<div class="btn-row"><button class="copy-btn" style="position:static" data-copy="' +
    e(window.reportToText(rep)) + '">copy report</button></div>';
}

// Dots on the category buttons so filtering never hides a failure.
function paintDots(rep) {
  const nav = document.getElementById('tab-overview');
  if (!nav || !nav.querySelectorAll) return;
  nav.querySelectorAll('.subtab').forEach((btn) => {
    const sec = OV_SECTION_BY_SUB[btn.dataset.subtab];
    const rows = sec ? rep.items.filter((i) => i.section === sec) : rep.items;
    const bad = rows.some((i) => i.status === 'bad');
    const warn = !bad && rows.some((i) => i.status === 'warn');
    btn.classList.toggle('has-fail', bad);
    btn.classList.toggle('has-warn', warn);
  });
}

// Repaint every panel that has been opened this session — only the visible one
// matters, but keeping them in sync means switching subtabs shows current data.
function paint() {
  if (!ovState) return;
  const rep = window.domainReport(ovState.raw);
  paintDots(rep);
  ovState.panels.forEach((panel, sub) => window.showResult(panel, reportHtml(ovState.raw, sub)));
}

// ---------- collection ----------

function collect(st) {
  const { domain, raw } = st;
  const alive = () => st.run === overviewRun;
  const repaint = () => { if (alive()) paint(); };
  const failKey = (k) => { if (raw.failed.indexOf(k) < 0) raw.failed.push(k); };

  // ---- wave 1: the zone itself, all in parallel ----
  const q = (name, type, key) => ovDns(name, type).then((r) => {
    if (!alive()) return;
    if (key === 'MX') raw.records.MX = r.value.map(ovMx).sort((x, y) => x.prio - y.prio);
    else raw.records[key] = r.value;
    if (!r.ok) failKey(key);
    if (r.nx) raw.nx = true;
    if (key === 'A') raw.ad = r.ad;
    repaint();
  });

  Promise.all([
    ...OV_TYPES.map((t) => q(domain, t, t)),
    ovDns(`_dmarc.${domain}`, 'TXT').then((r) => {
      if (!alive()) return;
      raw.dmarc = r.value;
      if (!r.ok) failKey('_dmarc');
      repaint();
    }),
    ...window.DKIM_SELECTORS.map((sel) => ovDns(`${sel}._domainkey.${domain}`, 'TXT').then((r) => {
      if (!alive()) return;
      raw.dkim[sel] = r.value;
      if (!r.ok) failKey('dkim');
      repaint();
    })),
    Promise.all(OV_PROP_RESOLVERS.map((key) =>
      window.dohQuery(domain, 'A', key)
        .then((d) => ({
          resolver: key, ok: true,
          // Sorted: round-robin DNS hands resolvers the same addresses in a
          // different order, which is not a propagation difference.
          answers: (d.Answer || []).filter((x) => Number(x.type) === 1).map((x) => String(x.data)).sort(),
        }))
        .catch(() => ({ resolver: key, ok: false, answers: [] }))))
      .then((results) => {
        if (!alive()) return;
        raw.propagation = { results };
        repaint();
      }),
  ]).then(() => {
    if (!alive()) return;
    wave2(st);
  }).catch(() => { if (alive()) wave2(st); });
}

function wave2(st) {
  const { domain, host, raw } = st;
  const alive = () => st.run === overviewRun;
  const repaint = () => { if (alive()) paint(); };
  const finish = (src) => { raw.pending = raw.pending.filter((s) => s !== src); };

  const ips = (raw.records.A || []).filter((x) => window.isIPv4(x) && !window.isPrivateIP(x));
  const mxHosts = (raw.records.MX || []).map((m) => m.host).filter(Boolean).slice(0, 4);

  // The RFC 7208 lookup budget can only be counted by following every include,
  // so run the same recursive walker the SPF Lookups tab uses. walkSpf() does
  // one TXT (and one A/MX) lookup per mechanism — all browser DoH, no API call —
  // and its visited set plus depth guard keep a hostile record from fanning out.
  const rootSpf = (raw.records.TXT || []).filter((t) => /^v=spf1/i.test(String(t).trim()))[0];
  if (rootSpf) {
    const ctx = { lookups: 0, voids: 0, visited: new Set() };
    const rootCount = (window.spfLookupTerms(rootSpf) || []).length;
    walkSpf(domain, ctx, 0).then((node) => {
      if (!alive()) return;
      finish('spfwalk');
      raw.spfWalk = node.error
        ? { error: `SPF walk stopped: ${node.error}.` }
        : { total: ctx.lookups, voids: ctx.voids, root: rootCount, dead: countStatuses(node, ['dead', 'error']) };
      repaint();
    }).catch(() => {
      if (!alive()) return;
      finish('spfwalk');
      raw.spfWalk = { error: 'The SPF include walk did not complete.' };
      repaint();
    });
  } else {
    finish('spfwalk');
    repaint();
  }

  // Reverse DNS of the web IP and of each MX host.
  [...ips.slice(0, 2), ...mxHosts].forEach((target) => {
    ovPtr(target).then((v) => { if (alive()) { raw.ptr[target] = v; repaint(); } });
  });

  // Who owns the address (ASN / org / rough location).
  if (ips[0]) {
    fetch(`https://ipwho.is/${encodeURIComponent(ips[0])}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((g) => {
        if (!alive()) return;
        const c = (g && g.connection) || {};
        raw.geo = g && g.success !== false
          ? { asn: c.asn, org: c.org, isp: c.isp, city: g.city, country: g.country_code }
          : null;
        finish('geo'); repaint();
      })
      .catch(() => { if (alive()) { finish('geo'); repaint(); } });
  } else {
    finish('geo');
    repaint();
  }

  // Blacklists — the web IP if we have one, otherwise a mail exchanger's.
  (async () => {
    let ip = ips[0] || null;
    if (!ip) {
      for (const m of mxHosts) {
        const a = await ovDns(m, 'A');
        const found = (a.value || []).find((x) => window.isIPv4(x) && !window.isPrivateIP(x));
        if (found) { ip = found; break; }
      }
    }
    if (!alive()) return;
    if (!ip) { finish('rbl'); raw.rbl = { error: 'No public IPv4 address to check against the blacklists.' }; repaint(); return; }
    const data = await ovJson(`/api/rbl?ip=${encodeURIComponent(ip)}`, 'Blacklist check failed');
    if (!alive()) return;
    finish('rbl');
    raw.rbl = data.error ? { error: data.error } : { ip, results: data.results || [] };
    repaint();
  })();

  // Web server: headers/redirect chain, then TLS.
  ovHttp(host).then((data) => {
    if (!alive()) return;
    finish('http');
    raw.http = data;
    repaint();
  });
  ovJson(`/api/tls?host=${encodeURIComponent(host)}`, 'TLS check failed').then((data) => {
    if (!alive()) return;
    finish('tls');
    raw.tls = data.error ? { error: data.error } : { grade: data.grade, issues: data.issues || [] };
    repaint();
  });

  // Registration via RDAP. TLDs without RDAP come back as raw whois text.
  ovJson(`/api/whois?q=${encodeURIComponent(domain)}`, 'Registration lookup failed').then((data) => {
    if (!alive()) return;
    finish('whois');
    raw.whois = data.raw
      ? { error: 'This registry publishes no structured RDAP data, so expiry and status were not checked.' }
      : data.error ? { error: data.error } : data;
    repaint();
  });
}

// ---------- entry point ----------

// Every subtab runs through this: validate the input, reuse (or start) the
// collection for that domain, then paint this panel from the shared state.
async function runOverviewSub(sub, query, panel) {
  const host = window.hostFromInput(query);
  if (window.isIP(host)) {
    window.showError(panel, 'Enter a domain name, not an IP — this report walks a whole zone. The DNS, Network, and Cloud tabs take an address.');
    return;
  }
  if (!window.isDomain(host)) {
    window.showError(panel, 'Enter a domain name, e.g. example.com');
    return;
  }
  const domain = window.reportDomain(host);
  if (!ovState || ovState.domain !== domain || ovState.host !== host) {
    const raw = {
      domain, now: Date.now(), records: {}, dkim: {}, ptr: {}, failed: [],
      pending: ['geo', 'rbl', 'http', 'tls', 'whois', 'spfwalk'],
    };
    ovState = { domain, host, raw, panels: new Map(), run: ++overviewRun };
    collect(ovState);
  }
  if (!panel.dataset.ovWired) {
    // Deep link into the detail tab for whatever the row is about.
    panel.addEventListener('click', (ev) => {
      const btn = ev.target && ev.target.closest ? ev.target.closest('[data-jump]') : null;
      if (btn) window.jumpTo(btn.getAttribute('data-jump'));
    });
    panel.dataset.ovWired = '1';
  }
  ovState.panels.set(sub, panel);
  paint();
}

Object.keys(OV_SECTION_BY_SUB).forEach((sub) => {
  window.registerRunner('overview', sub, (query, panel) => runOverviewSub(sub, query, panel));
});
