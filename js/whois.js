// whois.js — RDAP-based whois via /api/whois

async function runWhois(query, panel) {
  const q = window.hostFromInput(query);
  if (!window.isDomain(q) && !window.isIP(q)) { window.showError(panel, 'Enter a domain or IP address.'); return; }
  window.showLoading(panel, 'Looking up registration data…');
  try {
    const res = await fetch(`/api/whois?q=${encodeURIComponent(q)}`);
    if (!res.ok) {
      let msg = `Whois lookup failed (${res.status})`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    const d = await res.json();
    if (d.error) throw new Error(d.error);

    const isIP = window.isIP(q);
    let rows;
    if (isIP) {
      rows = [
        ['Network name', d.name], ['Handle', d.handle], ['CIDR', d.cidr],
        ['Country', d.country], ['Organization', d.org], ['Abuse contact', d.abuse],
        ['Registered', d.registered], ['Last changed', d.updated],
      ];
    } else {
      rows = [
        ['Registrar', d.registrar], ['Status', (d.status || []).join ? (d.status || []).join(', ') : d.status],
        ['Created', d.created], ['Updated', d.updated], ['Expires', d.expires],
        // Keep as an array so each name server is escaped, then joined with <br>.
        ['Name servers', d.nameservers || []],
        ['DNSSEC', d.dnssec],
      ];
    }
    // Array values render one-per-line (each element escaped); scalars are escaped as-is.
    const cell = (v) => Array.isArray(v)
      ? v.map((x) => window.escapeHtml(x)).join('<br>')
      : window.escapeHtml(v);
    const body = rows.filter(([, v]) => v && v.length).map(([k, v]) => `<tr><td>${k}</td><td>${cell(v)}</td></tr>`).join('');
    if (!body) {
      panel.innerHTML = `<div class="summary grey">No registration data returned. Try <a href="https://lookup.icann.org/en/lookup?name=${encodeURIComponent(q)}" target="_blank" rel="noopener">lookup.icann.org</a>.</div>`;
      return;
    }
    panel.innerHTML =
      window.card(`Whois — ${q}`, `<table><tbody>${body}</tbody></table>`) +
      `<div class="note">Data from RDAP. If a field is missing, some registries withhold it — try <a href="https://lookup.icann.org/en/lookup?name=${encodeURIComponent(q)}" target="_blank" rel="noopener">lookup.icann.org</a>.</div>`;
  } catch (e) {
    window.showError(panel, e.message || 'Whois lookup failed.');
  }
}

window.registerRunner('whois', 'main', runWhois);
