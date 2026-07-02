// dns.js — DNS Lookup + Propagation

const DNS_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV'];
const TYPE_NUM = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV' };

let dnsSelectedType = 'A';

function reverseInAddr(ip) {
  if (window.isIPv4(ip)) {
    return ip.trim().split('.').reverse().join('.') + '.in-addr.arpa';
  }
  return ip; // IPv6 reverse omitted for brevity
}

function typeName(n) { return TYPE_NUM[n] || String(n); }

// ---------- Lookup ----------
async function runDNSLookup(query, panel) {
  const isPtr = window.isIP(query);
  renderLookupControls(panel, isPtr);
  await doLookup(query, panel, dnsSelectedType);
}

function renderLookupControls(panel, isPtr) {
  const types = isPtr ? ['PTR'] : [...DNS_TYPES.filter((t) => t !== 'PTR'), 'ALL'];
  if (isPtr) dnsSelectedType = 'PTR';
  else if (dnsSelectedType === 'PTR') dnsSelectedType = 'A';
  const pills = types.map((t) =>
    `<button class="pill${t === dnsSelectedType ? ' active' : ''}" data-type="${t}">${t}</button>`
  ).join('');
  panel.innerHTML = `<div class="pills">${pills}</div><div class="result" id="dns-lookup-result"></div>`;
  panel.querySelectorAll('.pill').forEach((p) => {
    p.addEventListener('click', () => {
      dnsSelectedType = p.dataset.type;
      panel.querySelectorAll('.pill').forEach((x) => x.classList.toggle('active', x === p));
      const q = document.getElementById('query').value.trim();
      doLookup(q, panel, dnsSelectedType);
    });
  });
}

async function doLookup(query, panel, type) {
  const out = panel.querySelector('#dns-lookup-result');
  window.showLoading(out, `Looking up ${type} records…`);
  const lookupName = type === 'PTR' ? reverseInAddr(query) : query;
  try {
    if (type === 'ALL') {
      const wanted = DNS_TYPES.filter((t) => t !== 'PTR');
      const results = await Promise.all(wanted.map((t) =>
        window.dohQuery(query, t).then((d) => ({ t, d })).catch(() => ({ t, d: null }))
      ));
      let html = '';
      let any = false;
      results.forEach(({ t, d }) => {
        const rows = (d && d.Answer) ? d.Answer.filter((a) => typeName(a.type) === t) : [];
        if (rows.length) { any = true; html += recordCard(t, rows); }
      });
      out.innerHTML = any ? html : `<div class="summary grey">No records found for ${window.escapeHtml(query)}.</div>`;
      window.showResult(out, out.innerHTML);
    } else {
      const data = await window.dohQuery(lookupName, type);
      const rows = (data.Answer || []).filter((a) => typeName(a.type) === type);
      if (!rows.length) {
        out.innerHTML = `<div class="summary grey">No ${type} records found for ${window.escapeHtml(query)}.</div>`;
      } else {
        window.showResult(out, recordCard(type, rows));
      }
    }
  } catch (e) {
    window.showError(out, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

function recordCard(type, rows) {
  const body = `<table><thead><tr><th>Name</th><th>TTL</th><th>Type</th><th>Data</th></tr></thead><tbody>` +
    rows.map((r) =>
      `<tr><td>${window.escapeHtml(r.name)}</td><td>${r.TTL}</td><td>${type}</td>` +
      `<td class="data-cell"><span class="data-val">${window.escapeHtml(r.data)}</span>` +
      `<button class="copy-cell" data-copy="${window.escapeHtml(r.data)}" title="Copy this record">⧉</button></td></tr>`
    ).join('') + `</tbody></table>`;
  const copyText = rows.map((r) => `${r.name}\t${r.TTL}\t${type}\t${r.data}`).join('\n');
  return window.card(`${type} records`, body, copyText);
}

// ---------- Propagation ----------
// Queried directly from the browser (no server) against the public resolvers
// that expose a JSON DoH API with CORS. Others (Quad9, OpenDNS, AdGuard, …) don't
// send CORS headers or need non-standard ports, so a browser can't reach them.
const RESOLVERS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
  { name: 'DNS.SB', url: 'https://doh.sb/dns-query' },
];
const PROP_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
let propType = 'A';

async function queryResolver(resolver, name, type) {
  const sep = resolver.url.includes('?') ? '&' : '?';
  const url = `${resolver.url}${sep}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: { Accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(String(res.status));
  const data = await res.json();
  const rows = (data.Answer || []).filter((a) => typeName(a.type) === type);
  return { answers: rows.map((a) => String(a.data)).sort(), ttl: rows[0] ? rows[0].TTL : '' };
}

async function runDNSPropagation(query, panel) {
  const isPtr = window.isIP(query);
  const t = isPtr ? 'PTR' : propType;
  if (isPtr) propType = 'A';
  const pills = (isPtr ? ['PTR'] : PROP_TYPES).map((x) =>
    `<button class="pill${x === t ? ' active' : ''}" data-type="${x}">${x}</button>`
  ).join('');
  panel.innerHTML = `<div class="pills">${pills}</div><div class="result" id="dns-prop-result"></div>`;
  panel.querySelectorAll('.pill').forEach((p) => {
    p.addEventListener('click', () => {
      propType = p.dataset.type;
      panel.querySelectorAll('.pill').forEach((x) => x.classList.toggle('active', x === p));
      doPropagation(query, panel, propType);
    });
  });
  await doPropagation(query, panel, t);
}

async function doPropagation(query, panel, type) {
  const out = panel.querySelector('#dns-prop-result');
  window.showLoading(out, `Querying ${RESOLVERS.length} resolvers…`);
  const lookupName = type === 'PTR' ? reverseInAddr(query) : query;

  const results = await Promise.all(RESOLVERS.map((r) =>
    queryResolver(r, lookupName, type)
      .then((d) => ({ resolver: r.name, ok: true, answers: d.answers, ttl: d.ttl }))
      .catch(() => ({ resolver: r.name, ok: false, answers: [], ttl: '' }))
  ));

  const answered = results.filter((r) => r.ok && r.answers.length);
  const reference = answered.length ? answered[0].answers.join(', ') : '';
  const signatures = new Set(answered.map((r) => r.answers.join(', ')));
  const consistent = answered.length === results.filter((r) => r.ok).length && signatures.size === 1;

  const summary = consistent && answered.length
    ? `<div class="summary green">✓ Propagated consistently across all reachable resolvers.</div>`
    : (answered.length
        ? `<div class="summary yellow">⚠ Inconsistent — record may still be propagating.</div>`
        : `<div class="summary grey">No ${type} records returned by any resolver.</div>`);

  const rowsHtml = results.map((r) => {
    const answer = !r.ok ? '<span class="err">unreachable</span>'
      : (r.answers.map((x) => window.escapeHtml(x)).join('<br>') || '<span class="muted">— empty —</span>');
    let status;
    if (!r.ok) status = '<span class="err">error</span>';
    else if (!r.answers.length) status = '<span class="muted">no record</span>';
    else status = r.answers.join(', ') === reference ? '<span class="ok">match</span>' : '<span class="warn">differs</span>';
    return `<tr><td>${window.escapeHtml(r.resolver)}</td><td>${answer}</td><td>${window.escapeHtml(String(r.ttl || ''))}</td><td>${status}</td></tr>`;
  }).join('');

  const table = `<table><thead><tr><th>Resolver</th><th>Answer</th><th>TTL</th><th>Status</th></tr></thead><tbody>${rowsHtml}</tbody></table>`;
  out.innerHTML = summary + window.card(`${type} propagation`, table);
}

window.registerRunner('dns', 'lookup', runDNSLookup);
window.registerRunner('dns', 'propagation', runDNSPropagation);
