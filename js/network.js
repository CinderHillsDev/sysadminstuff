// network.js — ASN Lookup, Subnet Calculator, Geo, Reverse DNS

// ---------- ASN Lookup ----------
async function runASN(query, panel) {
  const q = query.trim();
  if (!window.isASN(q) && !window.isIP(q)) { window.showError(panel, 'Enter an ASN (AS13335 or 13335) or an IP address.'); return; }
  if (window.isIP(q) && window.isPrivateIP(q)) { window.showError(panel, `${q} is a private/reserved address (RFC1918) — it has no public ASN.`); return; }
  window.showLoading(panel, 'Querying bgpview.io…');
  try {
    const res = await fetch(`/api/asn?q=${encodeURIComponent(q)}`);
    if (!res.ok) {
      let msg = `ASN lookup failed (${res.status})`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    const d = await res.json();
    const info = `<table><tbody>
      <tr><td>ASN</td><td>${window.escapeHtml(d.asn ? 'AS' + d.asn : '—')}</td></tr>
      <tr><td>Name</td><td>${window.escapeHtml(d.name || '—')}</td></tr>
      <tr><td>Description</td><td>${window.escapeHtml(d.description || '—')}</td></tr>
      <tr><td>Country</td><td>${window.escapeHtml(d.country || '—')}</td></tr>
      ${d.ip ? `<tr><td>Matched IP</td><td>${window.escapeHtml(d.ip)}</td></tr>` : ''}
    </tbody></table>`;
    const prefixes = (d.prefixes || []);
    const prefHtml = prefixes.length
      ? `<table><thead><tr><th>Prefix</th><th>Description</th></tr></thead><tbody>${prefixes.map((p) => `<tr><td>${window.escapeHtml(p.prefix)}</td><td>${window.escapeHtml(p.description || '—')}</td></tr>`).join('')}</tbody></table>`
      : '<div class="muted">No announced prefixes returned.</div>';
    panel.innerHTML =
      window.card('ASN', info) +
      window.card(`Announced prefixes (${prefixes.length})`, prefHtml);
  } catch (e) {
    window.showError(panel, e.message || 'ASN lookup failed.');
  }
}

// ---------- Subnet Calculator (100% client-side) ----------
function runSubnet(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Calculated entirely in your browser.</div>
    <div class="btn-row">
      <input class="text-input" id="subnet-input" placeholder="192.168.1.0/24  or  10.0.0.5 255.255.255.0" style="flex:1;min-width:16rem" />
      <button class="btn primary" id="subnet-go">Calculate</button>
    </div>
    <div class="result" id="subnet-result"></div>`;
  const go = () => calcSubnet(panel);
  panel.querySelector('#subnet-go').addEventListener('click', go);
  panel.querySelector('#subnet-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  panel.dataset.wired = '1';
}

function calcSubnet(panel) {
  const out = panel.querySelector('#subnet-result');
  const raw = panel.querySelector('#subnet-input').value.trim();
  // parseCidrInput + subnetInfo are the shared, unit-tested math from core.js.
  const parsed = window.parseCidrInput(raw);
  if (!parsed) {
    window.showError(out, 'Enter a valid CIDR (192.168.1.0/24) or IP and mask.');
    return;
  }
  const info = window.subnetInfo(parsed.ip, parsed.bits);
  const rows = [
    ['CIDR', `${info.network}/${info.bits}`],
    ['Network address', info.network],
    ['Broadcast address', info.broadcast],
    ['Subnet mask', info.mask],
    ['Wildcard mask', info.wildcard],
    ['Usable host range', `${info.firstHost} – ${info.lastHost}`],
    ['Usable hosts', info.usableHosts.toLocaleString()],
    ['IP class', info.ipClass],
  ].map(([k, v]) => `<tr><td>${k}</td><td>${window.escapeHtml(v)}</td></tr>`).join('');
  const copyText = `Network: ${info.network}/${info.bits}\nBroadcast: ${info.broadcast}\nMask: ${info.mask}\nRange: ${info.firstHost} - ${info.lastHost}\nHosts: ${info.usableHosts}`;
  window.showResult(out, window.card(`${info.network}/${info.bits}`, `<table><tbody>${rows}</tbody></table>`, copyText));
}

// ---------- Geo ----------
async function runGeo(query, panel) {
  window.showLoading(panel, 'Resolving…');
  try {
    const ip = await window.resolveToIP(window.hostFromInput(query));
    if (window.isPrivateIP(ip)) { window.showError(panel, `${ip} is a private/reserved address (RFC1918) — it cannot be geolocated.`); return; }
    window.showLoading(panel, `Locating ${ip}…`);
    // ipwho.is — HTTPS + CORS, no API key, callable straight from the browser.
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error(`Geo lookup failed (${res.status})`);
    const d = await res.json();
    if (d.success === false) throw new Error(d.message || 'Geolocation not available for this IP.');
    const conn = d.connection || {};
    const flag = (d.flag && d.flag.emoji) || (d.country_code ? countryFlag(d.country_code) : '');
    const rows = [
      ['IP', d.ip], ['Country', (d.country || d.country_code) ? `${flag} ${d.country || ''} (${d.country_code || ''})`.trim() : ''],
      ['Region', d.region], ['City', d.city],
      ['ISP', conn.isp], ['Org', conn.org], ['ASN', conn.asn ? `AS${conn.asn}` : ''],
      ['Timezone', d.timezone && d.timezone.id],
    ].filter(([, v]) => v).map(([k, v]) => `<tr><td>${k}</td><td>${window.escapeHtml(v)}</td></tr>`).join('');
    panel.innerHTML =
      '<div class="note">Geolocation is approximate. Data from ipwho.is.</div>' +
      window.card(`Geolocation — ${ip}`, `<table><tbody>${rows}</tbody></table>`);
  } catch (e) {
    window.showError(panel, e.message || 'Geo lookup failed.');
  }
}
function countryFlag(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

// ---------- Reverse DNS ----------
async function runRDNS(query, panel) {
  const ip = query.trim();
  if (!window.isIPv4(ip)) { window.showError(panel, 'Enter an IPv4 address.'); return; }
  if (window.isPrivateIP(ip)) { window.showError(panel, `${ip} is a private/reserved address (RFC1918) — public DNS has no PTR for it.`); return; }
  window.showLoading(panel, 'Looking up PTR…');
  try {
    const rev = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    const data = await window.dohQuery(rev, 'PTR');
    const ptrs = (data.Answer || []).filter((a) => a.type === 12).map((a) => a.data.replace(/\.$/, ''));
    if (!ptrs.length) { panel.innerHTML = `<div class="summary grey">No PTR record found for ${window.escapeHtml(ip)}.</div>`; return; }

    // Forward-confirm each PTR hostname
    const rows = await Promise.all(ptrs.map(async (host) => {
      let confirmed = false, ips = [];
      try {
        const a = await window.dohQuery(host, 'A');
        ips = (a.Answer || []).filter((x) => x.type === 1).map((x) => x.data);
        confirmed = ips.includes(ip);
      } catch (e) { /* ignore */ }
      return `<tr><td>${window.escapeHtml(host)}</td><td>${confirmed ? '<span class="ok">✓ confirmed</span>' : '<span class="warn">✗ not confirmed</span>'}</td><td>${window.escapeHtml(ips.join(', ') || '—')}</td></tr>`;
    }));
    panel.innerHTML = window.card(`Reverse DNS — ${ip}`, `<table><thead><tr><th>PTR Record</th><th>Forward-confirmed</th><th>Resolves to</th></tr></thead><tbody>${rows.join('')}</tbody></table>`);
  } catch (e) {
    window.showError(panel, `Could not reach the DNS resolver. ${e.message || ''}`.trim());
  }
}

// ---------- CIDR tools ----------
function runCidr(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Calculated in your browser.</div>
    <div class="card"><h3>Is an IP inside a CIDR?</h3>
      <div class="btn-row">
        <input class="text-input" id="cc-cidr" placeholder="10.0.0.0/8" style="width:11rem">
        <input class="text-input" id="cc-ip" placeholder="10.5.6.7" style="width:11rem">
        <button class="btn primary" id="cc-go">Check</button>
      </div>
      <div class="result" id="cc-out"></div>
    </div>
    <div class="card"><h3>Split a CIDR into subnets</h3>
      <div class="btn-row">
        <input class="text-input" id="cs-cidr" placeholder="192.168.1.0/24" style="width:13rem">
        <label class="field-label" style="margin:0">into /<input class="text-input" id="cs-bits" placeholder="26" style="width:4rem"></label>
        <button class="btn primary" id="cs-go">Split</button>
      </div>
      <div class="result" id="cs-out"></div>
    </div>`;
  const ccOut = panel.querySelector('#cc-out');
  const check = () => {
    const r = window.cidrContains(panel.querySelector('#cc-cidr').value.trim(), panel.querySelector('#cc-ip').value.trim());
    if (r === null) { window.showError(ccOut, 'Enter a valid CIDR and IPv4 address.'); return; }
    ccOut.innerHTML = r
      ? '<div class="summary green">✓ Yes — the IP is inside that range.</div>'
      : '<div class="summary red">✗ No — the IP is outside that range.</div>';
  };
  const csOut = panel.querySelector('#cs-out');
  const split = () => {
    const list = window.splitCidr(panel.querySelector('#cs-cidr').value.trim(), panel.querySelector('#cs-bits').value.trim());
    if (list === null) { window.showError(csOut, 'Enter a valid CIDR and a longer prefix (≤1024 subnets).'); return; }
    const rows = list.map((c) => `<tr><td class="data-cell"><span class="data-val">${c}</span><button class="copy-cell" data-copy="${c}" title="Copy">⧉</button></td></tr>`).join('');
    csOut.innerHTML = window.card(`${list.length} subnets`, `<table><tbody>${rows}</tbody></table>`, list.join('\n'));
    window.wireCopyButtons(csOut);
  };
  panel.querySelector('#cc-go').addEventListener('click', check);
  panel.querySelector('#cs-go').addEventListener('click', split);
  panel.dataset.wired = '1';
}

window.registerRunner('network', 'asn', runASN);
window.registerRunner('network', 'cidr', runCidr);
window.registerRunner('network', 'subnet', runSubnet);
window.registerRunner('network', 'geo', runGeo);
window.registerRunner('network', 'rdns', runRDNS);
