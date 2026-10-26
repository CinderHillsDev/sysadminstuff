// overview.js — one input, everything checked.
//
// The same lookups the DNS / Email / Web / Whois tabs do individually, fired
// together and condensed into a scored report. Everything here is orchestration:
// what a finding *means* and what it costs lives in core.js's domainReport(),
// which is pure and unit-tested.
//
// Cost per report: ~25 DNS queries (issued straight from the browser via DoH —
// free, and only proxied through /api/dns when the network blocks public DoH)
// plus four Pages Function calls (/api/rbl, /api/headers, /api/tls, /api/whois)
// and one ipwho.is lookup.

const OV_TYPES = ['A', 'AAAA', 'NS', 'CNAME', 'SOA', 'DS', 'DNSKEY', 'CAA', 'TXT', 'MX'];
const OV_TYPE_NUM = {
  A: 1, AAAA: 28, NS: 2, CNAME: 5, SOA: 6, DS: 43, DNSKEY: 48, CAA: 257, TXT: 16, MX: 15, PTR: 12,
};
const OV_PROP_RESOLVERS = ['cloudflare', 'google', 'dnssb'];

// Bumped on every run so a slow response from a superseded run can't render
// over the report the user is now looking at.
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

function ensureOverviewSkeleton(panel) {
  let out = panel.querySelector('#ov-out');
  if (out) return out;
  panel.innerHTML =
    '<div class="note">One pass over a domain: DNS and DNSSEC, mail authentication (MX, SPF, DKIM, ' +
    'DMARC, blacklists), the web server (HTTPS, headers, TLS) and the registration. Lookups run in ' +
    'parallel; rows fill in as they land.</div><div id="ov-out"></div>';
  // Deep link into the detail tab for whatever the row is about. Delegated on the
  // panel so it survives the re-renders below.
  panel.addEventListener('click', (ev) => {
    const btn = ev.target && ev.target.closest ? ev.target.closest('[data-jump]') : null;
    if (btn) window.jumpTo(btn.getAttribute('data-jump'));
  });
  return panel.querySelector('#ov-out');
}

function renderReport(raw) {
  const rep = window.domainReport(raw);
  const e = window.escapeHtml;

  if (!rep.judged && !rep.items.some((i) => i.status === 'pending')) {
    return '<div class="summary red">Nothing could be checked. Every lookup failed — this network may be ' +
      'blocking DNS-over-HTTPS and the site&#39;s own resolver endpoints.</div>';
  }

  const headline = rep.items.filter((i) => i.status === 'bad' || i.status === 'warn');
  const head =
    `<div class="report-head"><div class="grade ${rep.grade}">${rep.grade}</div><div>` +
    `<div class="report-score">${rep.score}<span>/100</span></div>` +
    `<div class="muted">${e(raw.domain)} · ${rep.counts.ok} pass · ${rep.counts.warn} warn · ${rep.counts.bad} fail` +
    (rep.counts.pending ? ` · ${rep.counts.pending} still running` : '') + '</div></div></div>';

  const attention = headline.length
    ? window.card(`Needs attention (${headline.length})`, '<ul class="fixes">' + headline.map((i) =>
      `<li><span class="badge ${i.status === 'bad' ? 'red' : 'yellow'}">${i.status === 'bad' ? 'FAIL' : 'WARN'}</span> ` +
      `<strong>${e(i.label)}</strong> — ${e(i.detail)}` +
      (i.link ? ` <button class="row-link" data-jump="${e(i.link)}">open ${e(i.link.replace(':', ' > '))}</button>` : '') +
      '</li>').join('') + '</ul>')
    : '<div class="summary green">✓ Nothing failed and nothing is warning — see the detail below.</div>';

  const mark = { ok: 'green', warn: 'yellow', bad: 'red', info: 'grey', pending: 'grey' };
  const word = { ok: 'PASS', warn: 'WARN', bad: 'FAIL', info: 'INFO', pending: '…' };
  const sections = ['DNS', 'Email', 'Web', 'Registration'];
  const bodies = sections.map((section) => {
    const rows = rep.items.filter((i) => i.section === section);
    if (!rows.length) return '';
    return window.card(section, '<table class="report-table"><tbody>' + rows.map((i) =>
      `<tr${i.status === 'bad' ? ' class="fail"' : ''}><td class="st"><span class="badge ${mark[i.status]}">${word[i.status]}</span></td>` +
      `<td class="lbl">${e(i.label)}</td>` +
      `<td class="dt">${i.status === 'pending' ? '<span class="muted">checking\u2026</span>' : e(i.detail)}</td>` +
      `<td class="ln">${i.link && i.status !== 'pending' ? `<button class="row-link" data-jump="${e(i.link)}">detail \u2192</button>` : ''}</td></tr>`
    ).join('') + '</tbody></table>');
  }).join('');

  const records = raw.records;
  const rawBits = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT', 'CAA', 'SOA'].filter((t) => (records[t] || []).length)
    .map((t) => `<tr><td>${t}</td><td>${records[t].map((v) => e(typeof v === 'object' ? `${v.prio} ${v.host}` : v)).join('<br>')}</td></tr>`)
    .join('');
  const appendix = rawBits
    ? window.card('Records seen', `<table class="headers-table"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>${rawBits}</tbody></table>`)
    : '';

  return head + attention + bodies + appendix +
    '<div class="btn-row"><button class="copy-btn" style="position:static" data-copy="' +
    e(window.reportToText(rep)) + '">copy report</button></div>';
}

async function runOverview(query, panel) {
  const run = ++overviewRun;
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
  const raw = {
    domain, now: Date.now(), records: {}, dkim: {}, ptr: {}, failed: [],
    pending: ['geo', 'rbl', 'http', 'tls', 'whois', 'spfwalk'],
  };
  const out = ensureOverviewSkeleton(panel);
  const alive = () => run === overviewRun;
  const paint = () => { if (alive()) window.showResult(out, renderReport(raw)); };
  const finish = (src) => { raw.pending = raw.pending.filter((s) => s !== src); };
  const failKey = (k) => { if (raw.failed.indexOf(k) < 0) raw.failed.push(k); };
  paint();

  // ---- wave 1: the zone itself, all in parallel ----
  const q = (name, type, key) => ovDns(name, type).then((r) => {
    if (!alive()) return;
    if (key === 'MX') raw.records.MX = r.value.map(ovMx).sort((x, y) => x.prio - y.prio);
    else raw.records[key] = r.value;
    if (!r.ok) failKey(key);
    if (r.nx) raw.nx = true;
    if (key === 'A') raw.ad = r.ad;
    paint();
  });

  await Promise.all([
    ...OV_TYPES.map((t) => q(domain, t, t)),
    ovDns(`_dmarc.${domain}`, 'TXT').then((r) => {
      if (!alive()) return;
      raw.dmarc = r.value;
      if (!r.ok) failKey('_dmarc');
      paint();
    }),
    ...window.DKIM_SELECTORS.map((sel) => ovDns(`${sel}._domainkey.${domain}`, 'TXT').then((r) => {
      if (!alive()) return;
      raw.dkim[sel] = r.value;
      if (!r.ok) failKey('dkim');
      paint();
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
        paint();
      }),
  ]);

  if (!alive()) return;

  // ---- wave 2: the things that need an address from wave 1 ----
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
      paint();
    }).catch(() => {
      if (!alive()) return;
      finish('spfwalk');
      raw.spfWalk = { error: 'The SPF include walk did not complete.' };
      paint();
    });
  } else {
    finish('spfwalk');
  }

  // Reverse DNS of the web IP and of each MX host.
  [...ips.slice(0, 2), ...mxHosts].forEach((target) => {
    ovPtr(target).then((v) => { if (alive()) { raw.ptr[target] = v; paint(); } });
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
        finish('geo'); paint();
      })
      .catch(() => { if (alive()) { finish('geo'); paint(); } });
  } else {
    finish('geo');
  }

  // Blacklists — the web IP if we have one, otherwise a mail exchanger's.
  const rblFrom = async () => {
    if (ips[0]) return ips[0];
    for (const m of mxHosts) {
      const a = await ovDns(m, 'A');
      const ip = (a.value || []).find((x) => window.isIPv4(x) && !window.isPrivateIP(x));
      if (ip) return ip;
    }
    return null;
  };
  rblFrom().then((ip) => {
    if (!alive()) return;
    if (!ip) { finish('rbl'); raw.rbl = { error: 'No public IPv4 address to check against the blacklists.' }; paint(); return; }
    ovJson(`/api/rbl?ip=${encodeURIComponent(ip)}`, 'Blacklist check failed').then((data) => {
      if (!alive()) return;
      finish('rbl');
      raw.rbl = data.error ? { error: data.error } : { ip, results: data.results || [] };
      paint();
    });
  });

  // Web server: headers/redirect chain, then TLS.
  ovHttp(host).then((data) => {
    if (!alive()) return;
    finish('http');
    raw.http = data;
    paint();
  });
  ovJson(`/api/tls?host=${encodeURIComponent(host)}`, 'TLS check failed').then((data) => {
    if (!alive()) return;
    finish('tls');
    raw.tls = data.error ? { error: data.error } : { grade: data.grade, issues: data.issues || [] };
    paint();
  });

  // Registration via RDAP. TLDs without RDAP come back as raw whois text.
  ovJson(`/api/whois?q=${encodeURIComponent(domain)}`, 'Registration lookup failed').then((data) => {
    if (!alive()) return;
    finish('whois');
    raw.whois = data.raw
      ? { error: 'This registry publishes no structured RDAP data, so expiry and status were not checked.' }
      : data.error ? { error: data.error } : data;
    paint();
  });
}

window.registerRunner('overview', 'main', runOverview);
