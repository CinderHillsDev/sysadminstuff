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
      `<tr><td>${window.escapeHtml(r.name)}</td><td>${r.TTL}</td><td>${type}</td><td>${window.escapeHtml(r.data)}</td></tr>`
    ).join('') + `</tbody></table>`;
  const copyText = rows.map((r) => `${r.name}\t${r.TTL}\t${type}\t${r.data}`).join('\n');
  return window.card(`${type} records`, body, copyText);
}

// ---------- Propagation ----------
const RESOLVERS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
  { name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query' },
  { name: 'Quad9', url: 'https://dns.quad9.net/dns-query' },
  { name: 'AdGuard', url: 'https://dns.adguard.com/dns-query' },
];
const PROP_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
let propType = 'A';

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

async function queryResolver(resolver, name, type) {
  const sep = resolver.url.includes('?') ? '&' : '?';
  const url = `${resolver.url}${sep}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: { Accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

async function doPropagation(query, panel, type) {
  const out = panel.querySelector('#dns-prop-result');
  window.showLoading(out, `Querying ${RESOLVERS.length} resolvers…`);
  const lookupName = type === 'PTR' ? reverseInAddr(query) : query;
  const results = await Promise.all(RESOLVERS.map((r) =>
    queryResolver(r, lookupName, type)
      .then((d) => {
        const rows = (d.Answer || []).filter((a) => typeName(a.type) === type);
        return { resolver: r.name, ok: true, answers: rows.map((a) => a.data).sort(), ttl: rows[0] ? rows[0].TTL : '' };
      })
      .catch(() => ({ resolver: r.name, ok: false, answers: [], ttl: '' }))
  ));

  const signatures = results.filter((r) => r.ok).map((r) => r.answers.join(', '));
  const uniq = new Set(signatures.filter((s) => s !== ''));
  const consistent = uniq.size <= 1 && signatures.some((s) => s !== '');

  const summary = consistent
    ? `<div class="summary green">✓ Propagated consistently across all resolvers.</div>`
    : `<div class="summary yellow">⚠ Inconsistent — record may still be propagating.</div>`;

  const rowsHtml = results.map((r) => {
    const answer = r.ok ? (r.answers.join('<br>') || '<span class="muted">— empty —</span>') : '<span class="err">unreachable</span>';
    const status = !r.ok ? '<span class="err">error</span>'
      : (r.answers.join(', ') === (signatures.find((s) => s !== '') || '') ? '<span class="ok">match</span>' : '<span class="warn">differs</span>');
    return `<tr><td>${r.resolver}</td><td>${answer}</td><td>${r.ttl}</td><td>${status}</td></tr>`;
  }).join('');

  const table = `<table><thead><tr><th>Resolver</th><th>Answer</th><th>TTL</th><th>Status</th></tr></thead><tbody>${rowsHtml}</tbody></table>`;
  out.innerHTML = summary + window.card(`${type} propagation`, table);
}

window.registerRunner('dns', 'lookup', runDNSLookup);
window.registerRunner('dns', 'propagation', runDNSPropagation);
