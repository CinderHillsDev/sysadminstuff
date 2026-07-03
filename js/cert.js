// cert.js — certificate info via crt.sh

async function runCert(query, panel) {
  const domain = window.hostFromInput(query);
  if (!window.isDomain(domain)) { window.showError(panel, 'Enter a domain name.'); return; }
  window.showLoading(panel, 'Querying crt.sh… (can be slow)');
  try {
    // Proxied through /api/crtsh because crt.sh sends no CORS headers.
    const res = await fetch(`/api/crtsh?q=${encodeURIComponent(domain)}`);
    if (!res.ok) {
      let msg = `crt.sh returned ${res.status}. It is sometimes slow or rate-limited — try again shortly.`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    let certs = await res.json();
    if (!Array.isArray(certs) || !certs.length) { panel.innerHTML = `<div class="summary grey">No certificates found for ${window.escapeHtml(domain)}.</div>`; return; }

    // De-dupe by cert id, sort by not_after desc
    const seen = new Set();
    certs = certs.filter((c) => { const k = c.id || (c.serial_number + c.not_after); if (seen.has(k)) return false; seen.add(k); return true; });
    certs.sort((a, b) => new Date(b.not_after) - new Date(a.not_after));

    const primary = certs[0];
    panel.innerHTML = certCard(primary, domain, true) + historyBlock(certs.slice(1, 6), domain);
  } catch (e) {
    window.showError(panel, e.message || 'Certificate lookup failed.');
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

// ---------- Decode a pasted PEM certificate or CSR (100% client-side) ----------
function kv(rows) {
  return `<table><tbody>${rows.filter(([, v]) => v != null && v !== '').map(([k, v]) =>
    `<tr><td>${k}</td><td class="data-cell"><span class="data-val">${v}</span><button class="copy-cell" data-copy="${window.escapeHtml(String(v).replace(/<[^>]+>/g, ''))}" title="Copy">⧉</button></td></tr>`).join('')}</tbody></table>`;
}
function keyDesc(c) {
  if (c.keyAlgo === 'RSA') return `RSA ${c.keySize}-bit`;
  if (c.keyAlgo === 'EC') return `EC ${c.keySize || ''}`.trim();
  return c.keyAlgo;
}
function sansHtml(sans) {
  return sans && sans.length ? sans.map((s) => window.escapeHtml(s)).join('<br>') : '<span class="muted">none</span>';
}

function renderCert(c, out) {
  if (!c) { window.showError(out, 'Could not parse that as an X.509 certificate. Check it is a valid PEM.'); return; }
  const now = new Date(), na = new Date(c.notAfter), nb = new Date(c.notBefore);
  const remaining = Math.round((na - now) / 86400000);
  const badge = remaining < 0 ? '<span class="badge red">EXPIRED</span>'
    : remaining <= 30 ? '<span class="badge yellow">EXPIRING SOON</span>' : '<span class="badge green">VALID</span>';
  out.innerHTML = window.card('Certificate', kv([
    ['Status', `${badge} ${remaining >= 0 ? remaining + ' days left' : Math.abs(remaining) + ' days ago'}`],
    ['Subject', window.escapeHtml(c.subject)],
    ['Issuer', window.escapeHtml(c.issuer)],
    ['SANs', sansHtml(c.sans)],
    ['Serial', c.serial],
    ['Valid from', nb.toISOString().replace('.000', '')],
    ['Valid to', na.toISOString().replace('.000', '')],
    ['Public key', window.escapeHtml(keyDesc(c))],
    ['Signature', window.escapeHtml(c.sigAlgo)],
  ]));
  window.wireCopyButtons(out);
}
function renderCsr(c, out) {
  if (!c) { window.showError(out, 'Could not parse that as a PKCS#10 CSR. Check it is a valid PEM.'); return; }
  out.innerHTML =
    `<div class="summary blue">Certificate Signing Request</div>` +
    window.card('CSR', kv([
      ['Subject', window.escapeHtml(c.subject)],
      ['Requested SANs', sansHtml(c.sans)],
      ['Public key', window.escapeHtml(keyDesc(c))],
      ['Signature', window.escapeHtml(c.sigAlgo)],
    ]));
  window.wireCopyButtons(out);
}

function runDecode(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Decoded entirely in your browser — your certificate or CSR is never uploaded.</div>
    <textarea class="mono" id="dec-in" placeholder="Paste a PEM certificate (-----BEGIN CERTIFICATE-----) or CSR (-----BEGIN CERTIFICATE REQUEST-----)…" style="min-height:11rem"></textarea>
    <div class="btn-row"><button class="btn primary" id="dec-go">Decode</button></div>
    <div class="result" id="dec-out"></div>`;
  const inp = panel.querySelector('#dec-in');
  const out = panel.querySelector('#dec-out');
  const go = () => {
    const pem = inp.value.trim();
    if (!pem) { out.innerHTML = ''; return; }
    if (/CERTIFICATE REQUEST/i.test(pem) || /NEW CERTIFICATE REQUEST/i.test(pem)) renderCsr(window.parseCsr(pem), out);
    else renderCert(window.parseCertificate(pem), out);
  };
  panel.querySelector('#dec-go').addEventListener('click', go);
  panel.dataset.wired = '1';
}

window.registerRunner('cert', 'lookup', runCert);
window.registerRunner('cert', 'decode', runDecode);
