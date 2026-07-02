// web.js — HTTP Headers, Redirects, TLS Grade

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
];

async function fetchChain(url) {
  const res = await fetch(`/api/headers?url=${encodeURIComponent(url)}`);
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
    throw new Error(msg);
  }
  return res.json();
}

// ---------- HTTP Headers ----------
async function runHTTPHeaders(query, panel) {
  if (!window.isURL(query)) { window.showError(panel, 'Enter a valid URL or hostname.'); return; }
  const url = window.normalizeURL(query);
  window.showLoading(panel, 'Fetching headers…');
  try {
    const chain = await fetchChain(url);
    const final = Array.isArray(chain) ? chain[chain.length - 1] : chain;
    const headers = final.headers || {};
    const keys = Object.keys(headers).sort();
    const allRows = keys.map((k) => `<tr><td>${window.escapeHtml(k)}</td><td>${window.escapeHtml(headers[k])}</td></tr>`).join('');

    const present = SECURITY_HEADERS.filter((h) => Object.keys(headers).some((k) => k.toLowerCase() === h));
    const secRows = SECURITY_HEADERS.map((h) => {
      const has = present.includes(h);
      const label = h.split('-').map((w) => w[0].toUpperCase() + w.slice(1)).join('-');
      return `<tr><td>${label}</td><td>${has ? '<span class="ok">present ✓</span>' : '<span class="warn">missing</span>'}</td></tr>`;
    }).join('');
    const score = present.length;
    const scoreCls = score >= 6 ? 'green' : (score >= 3 ? 'yellow' : 'red');

    panel.innerHTML =
      `<div class="summary ${scoreCls}">Security headers: ${score}/7 present · final status ${window.escapeHtml(String(final.status))}</div>` +
      window.card('Security headers', `<table><thead><tr><th>Header</th><th>Status</th></tr></thead><tbody>${secRows}</tbody></table>`) +
      window.card('All response headers', `<table><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${allRows}</tbody></table>`);
  } catch (e) {
    window.showError(panel, e.message || 'Could not fetch headers.');
  }
}

// ---------- Redirects ----------
async function runRedirects(query, panel) {
  if (!window.isURL(query)) { window.showError(panel, 'Enter a valid URL or hostname.'); return; }
  const url = window.normalizeURL(query);
  window.showLoading(panel, 'Following redirects…');
  try {
    const chain = await fetchChain(url);
    const hops = Array.isArray(chain) ? chain : [chain];
    const rows = hops.map((h, i) => {
      const isLast = i === hops.length - 1;
      const code = Number(h.status);
      const cls = code === 301 ? 'ok' : (code === 302 || code === 307 || code === 308 ? 'warn' : 'muted');
      const loc = (h.headers && (h.headers.location || h.headers.Location)) || (isLast ? '(destination)' : '');
      return `<li><strong>${i + 1}.</strong> <span class="${cls}">${code}</span> ${window.escapeHtml(h.url)}${loc && !isLast ? `<br><span class="muted">→ ${window.escapeHtml(loc)}</span>` : ''}${isLast ? ' <span class="badge green">final</span>' : ''}</li>`;
    }).join('');
    const warn = hops.length > 4 ? `<div class="summary yellow">⚠ ${hops.length - 1} redirects — long chains slow page loads.</div>` : '';
    panel.innerHTML = warn + window.card(`Redirect chain (${hops.length - 1} redirect${hops.length - 1 === 1 ? '' : 's'})`, `<ul class="chain">${rows}</ul>`);
  } catch (e) {
    window.showError(panel, e.message || 'Could not follow redirects.');
  }
}

// ---------- TLS Grade ----------
async function runTLS(query, panel) {
  const host = window.hostFromInput(query);
  if (!host) { window.showError(panel, 'Enter a hostname.'); return; }
  window.showLoading(panel, `Negotiating TLS with ${host}…`);
  try {
    const res = await fetch(`/api/tls?host=${encodeURIComponent(host)}`);
    if (!res.ok) {
      let msg = `TLS check failed (${res.status})`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    const data = await res.json();
    const grade = data.grade || 'F';
    const versions = data.versions || [];
    const verRows = versions.map((v) =>
      `<tr><td>${window.escapeHtml(v.version)}</td><td>${v.supported ? '<span class="ok">✓ supported</span>' : '<span class="muted">✗</span>'}</td><td>${window.escapeHtml(v.cipher || '—')}</td></tr>`
    ).join('');
    const issues = (data.issues || []);
    const issuesHtml = issues.length
      ? `<ul>${issues.map((i) => `<li class="warn">${window.escapeHtml(i)}</li>`).join('')}</ul>`
      : '<div class="ok">No issues detected.</div>';
    panel.innerHTML =
      window.card('TLS Grade',
        `<div style="display:flex;align-items:center;gap:1rem"><div class="grade ${grade}">${grade}</div><div>${window.escapeHtml(host)}${data.cert && data.cert.subject ? '<br><span class="muted">' + window.escapeHtml(data.cert.subject) + '</span>' : ''}</div></div>`) +
      window.card('Protocol support', `<table><thead><tr><th>Version</th><th>Supported</th><th>Negotiated cipher</th></tr></thead><tbody>${verRows}</tbody></table>`) +
      window.card('Issues', issuesHtml);
  } catch (e) {
    window.showError(panel, e.message || 'Could not complete TLS check.');
  }
}

window.registerRunner('web', 'httpheaders', runHTTPHeaders);
window.registerRunner('web', 'redirects', runRedirects);
window.registerRunner('web', 'tls', runTLS);
