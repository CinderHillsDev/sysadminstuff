// cert.js — certificate info via crt.sh

async function runCert(query, panel) {
  const domain = window.hostFromInput(query);
  if (!window.isDomain(domain)) { window.showError(panel, 'Enter a domain name.'); return; }
  window.showLoading(panel, 'Querying crt.sh… (can be slow)');
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
    if (!res.ok) throw new Error(`crt.sh returned ${res.status}. It is sometimes slow or rate-limited — try again shortly.`);
    const text = await res.text();
    let certs;
    try { certs = JSON.parse(text); } catch (e) { throw new Error('crt.sh returned an unexpected response. Try again shortly.'); }
    if (!certs.length) { panel.innerHTML = `<div class="summary grey">No certificates found for ${window.escapeHtml(domain)}.</div>`; return; }

    // De-dupe by cert id, sort by not_after desc
    const seen = new Set();
    certs = certs.filter((c) => { const k = c.id || (c.serial_number + c.not_after); if (seen.has(k)) return false; seen.add(k); return true; });
    certs.sort((a, b) => new Date(b.not_after) - new Date(a.not_after));

    const primary = certs[0];
    panel.innerHTML = certCard(primary, domain, true) + historyBlock(certs.slice(1, 6), domain);
  } catch (e) {
    if (/Failed to fetch|NetworkError|Load failed/i.test(e.message)) {
      window.showError(panel, 'Could not reach crt.sh. It occasionally blocks cross-origin requests or is slow — try again in a moment.');
    } else {
      window.showError(panel, e.message || 'Certificate lookup failed.');
    }
  }
}

function daysBetween(a, b) { return Math.round((b - a) / 86400000); }

function certCard(c, domain, primary) {
  const now = new Date();
  const notBefore = new Date(c.not_before);
  const notAfter = new Date(c.not_after);
  const remaining = daysBetween(now, notAfter);
  let badge;
  if (remaining < 0) badge = '<span class="badge red">EXPIRED</span>';
  else if (remaining <= 30) badge = `<span class="badge yellow">EXPIRING SOON</span>`;
  else badge = '<span class="badge green">VALID</span>';

  const sans = (c.name_value || '').split(/\n/).map((s) => s.trim()).filter(Boolean);
  const sansHtml = sans.map((s) =>
    s.toLowerCase().includes(domain.toLowerCase()) ? `<strong class="ok">${window.escapeHtml(s)}</strong>` : window.escapeHtml(s)
  ).join(', ');

  // SANs and status/date/id cells are pre-built safe HTML; the raw crt.sh string
  // fields (CN, issuer, serial) must be escaped — they are third-party data.
  const rows = [
    ['Status', `${badge} ${remaining >= 0 ? remaining + ' days remaining' : Math.abs(remaining) + ' days ago'}`],
    ['Common Name', window.escapeHtml(c.common_name || '—')],
    ['SANs', sansHtml || '—'],
    ['Issuer', window.escapeHtml(c.issuer_name || '—')],
    ['Valid from', notBefore.toISOString().slice(0, 10)],
    ['Valid to', notAfter.toISOString().slice(0, 10)],
    ['Serial', window.escapeHtml(c.serial_number || '—')],
    ['crt.sh ID', c.id ? `<a href="https://crt.sh/?id=${encodeURIComponent(c.id)}" target="_blank" rel="noopener">${window.escapeHtml(String(c.id))}</a>` : '—'],
  ].map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('');
  return window.card(primary ? `Certificate — ${domain}` : `Historical certificate`, `<table><tbody>${rows}</tbody></table>`);
}

function historyBlock(certs, domain) {
  if (!certs.length) return '';
  const inner = certs.map((c) => {
    const notAfter = new Date(c.not_after).toISOString().slice(0, 10);
    return `<tr><td>${window.escapeHtml(c.common_name || '—')}</td><td>${window.escapeHtml(c.issuer_name || '—')}</td><td>${notAfter}</td><td>${c.id ? `<a href="https://crt.sh/?id=${encodeURIComponent(c.id)}" target="_blank" rel="noopener">${window.escapeHtml(String(c.id))}</a>` : '—'}</td></tr>`;
  }).join('');
  return `<details><summary>Show ${certs.length} more recent certificate${certs.length === 1 ? '' : 's'}</summary>` +
    window.card('', `<table><thead><tr><th>Common Name</th><th>Issuer</th><th>Expires</th><th>ID</th></tr></thead><tbody>${inner}</tbody></table>`) +
    `</details>`;
}

window.registerRunner('cert', 'main', runCert);
