// cert.js — decode a pasted PEM certificate or CSR (100% client-side)

// rows: [label, displayHtml, copyText?]. A copy button is shown only when an
// explicit plain-text copyText is given (no HTML-stripping guesswork).
function kv(rows) {
  return `<table><tbody>${rows.filter(([, v]) => v != null && v !== '').map(([k, v, copy]) => {
    const btn = copy != null ? `<button class="copy-cell" data-copy="${window.escapeHtml(String(copy))}" title="Copy">⧉</button>` : '';
    return `<tr><td>${k}</td><td class="data-cell"><span class="data-val">${v}</span>${btn}</td></tr>`;
  }).join('')}</tbody></table>`;
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
    ['Subject', window.escapeHtml(c.subject), c.subject],
    ['Issuer', window.escapeHtml(c.issuer), c.issuer],
    ['SANs', sansHtml(c.sans), (c.sans || []).join('\n')],
    ['Serial', window.escapeHtml(c.serial), c.serial],
    ['Valid from', nb.toISOString().replace('.000', ''), nb.toISOString().replace('.000', '')],
    ['Valid to', na.toISOString().replace('.000', ''), na.toISOString().replace('.000', '')],
    ['Public key', window.escapeHtml(keyDesc(c)), keyDesc(c)],
    ['Signature', window.escapeHtml(c.sigAlgo), c.sigAlgo],
  ]));
  window.wireCopyButtons(out);
}
function renderCsr(c, out) {
  if (!c) { window.showError(out, 'Could not parse that as a PKCS#10 CSR. Check it is a valid PEM.'); return; }
  out.innerHTML =
    '<div class="summary blue">Certificate Signing Request</div>' +
    window.card('CSR', kv([
      ['Subject', window.escapeHtml(c.subject), c.subject],
      ['Requested SANs', sansHtml(c.sans), (c.sans || []).join('\n')],
      ['Public key', window.escapeHtml(keyDesc(c)), keyDesc(c)],
      ['Signature', window.escapeHtml(c.sigAlgo), c.sigAlgo],
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

// ---------- CAA ----------
// Per RFC 8659 a CA climbs from the name to its parents until it finds a CAA set,
// so we do the same rather than only checking the exact name.
async function runCAA(query, panel) {
  const domain = window.hostFromInput(query);
  window.showLoading(panel, 'Looking up CAA…');
  try {
    let records = [];
    let foundAt = '';
    for (const name of window.caaCandidates(domain)) {
      const data = await window.dohQuery(name, 'CAA');
      records = (data.Answer || []).filter((a) => a.type === 257)
        .map((a) => window.parseCaaRdata(a.data)).filter(Boolean);
      if (records.length) { foundAt = name; break; }
    }
    if (!records.length) {
      panel.innerHTML = `<div class="summary yellow">No CAA records for ${window.escapeHtml(domain)} or its parent domains — <strong>any</strong> CA may issue certificates. Add a CAA record to restrict this.</div>`;
      return;
    }
    const issuers = records.filter((r) => r.tag === 'issue' || r.tag === 'issuewild').map((r) => r.value || '(none — issuance forbidden)');
    const inherited = foundAt !== domain.toLowerCase().replace(/\.$/, '')
      ? ` <span class="muted">(inherited from ${window.escapeHtml(foundAt)} — ${window.escapeHtml(domain)} has no CAA of its own)</span>` : '';
    const rows = records.map((r) =>
      `<tr><td>${r.flags}</td><td><span class="badge ${r.tag.startsWith('issue') ? 'green' : 'grey'}">${window.escapeHtml(r.tag)}</span></td><td>${window.escapeHtml(r.value || '—')}</td></tr>`
    ).join('');
    panel.innerHTML =
      `<div class="summary green">Certificate issuance restricted to: ${window.escapeHtml([...new Set(issuers)].join(', ') || 'see below')}.${inherited}</div>` +
      window.card(`CAA records — ${foundAt}`, `<table><thead><tr><th>Flags</th><th>Tag</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>`);
  } catch (e) {
    window.showError(panel, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

window.registerRunner('cert', 'main', runDecode);
window.registerRunner('cert', 'caa', runCAA);
