// network.js — ASN Lookup, Subnet Calculator, Geo, Reverse DNS

// ---------- ASN Lookup ----------
async function runASN(query, panel) {
  const q = query.trim();
  if (!window.isASN(q) && !window.isIP(q)) { window.showError(panel, 'Enter an ASN (AS13335 or 13335) or an IP address.'); return; }
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
    window.showLoading(panel, `Locating ${ip}…`);
    const fields = 'status,message,country,countryCode,regionName,city,isp,org,as,query,reverse';
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`);
    if (res.status === 429) throw new Error('Rate limit reached (45 req/min). Wait a moment and try again.');
    if (!res.ok) throw new Error(`Geo lookup failed (${res.status})`);
    const d = await res.json();
    if (d.status !== 'success') throw new Error(d.message || 'Geo lookup failed.');
    const flag = d.countryCode ? countryFlag(d.countryCode) : '';
    const rows = [
      ['IP', d.query], ['Country', `${flag} ${d.country || ''} (${d.countryCode || ''})`],
      ['Region', d.regionName], ['City', d.city], ['ISP', d.isp], ['Org', d.org], ['ASN', d.as], ['Reverse DNS', d.reverse],
    ].filter(([, v]) => v).map(([k, v]) => `<tr><td>${k}</td><td>${window.escapeHtml(v)}</td></tr>`).join('');
    panel.innerHTML =
      `<div class="note">Geolocation is approximate.</div>` +
      window.card(`Geolocation — ${ip}`, `<table><tbody>${rows}</tbody></table>`);
  } catch (e) {
    if (/Failed to fetch|NetworkError|Load failed/i.test(e.message)) {
      window.showError(panel, 'ip-api.com only serves HTTP on its free tier, which browsers block from an HTTPS page. Try it directly at https://ip-api.com, or use a paid HTTPS endpoint.');
    } else {
      window.showError(panel, e.message || 'Geo lookup failed.');
    }
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

window.registerRunner('network', 'asn', runASN);
window.registerRunner('network', 'subnet', runSubnet);
window.registerRunner('network', 'geo', runGeo);
window.registerRunner('network', 'rdns', runRDNS);
