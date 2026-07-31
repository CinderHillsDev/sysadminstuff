// myip.js — "What's my IP" — reflect the caller's public IP + ASN/geo/edge info
// via /api/myip. Self-contained: needs no query, runs when the tab is opened.

function countryFlagFromCode(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

async function runMyIP(_query, panel) {
  window.showLoading(panel, 'Detecting your public IP…');
  try {
    const res = await fetch('/api/myip', { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`Lookup failed (${res.status})`);
    const d = await res.json();
    if (!d.ip) throw new Error('Could not determine your public IP.');

    const flag = d.country ? countryFlagFromCode(d.country) : '';
    const location = [d.city, d.regionCode || d.region, d.country ? `${flag} ${d.country}`.trim() : '']
      .filter(Boolean).join(', ');

    // Big, copyable IP up top — the thing people actually came for.
    const ipCard = window.card('Your public IP', `<div class="bigip">${window.escapeHtml(d.ip)}</div>`, d.ip);

    const netRows = [
      ['ASN', d.asn != null ? `AS${d.asn}` : ''],
      ['Provider', d.org],
      ['Location', location],
      ['Postal code', d.postalCode],
      ['Timezone', d.timezone],
      ['Coordinates', (d.latitude && d.longitude) ? `${d.latitude}, ${d.longitude}` : ''],
    ].filter(([, v]) => v)
      .map(([k, v]) => `<tr><td>${k}</td><td>${window.escapeHtml(v)}</td></tr>`).join('');

    const connRows = [
      ['Cloudflare edge (colo)', d.colo],
      ['HTTP protocol', d.httpProtocol],
      ['TLS version', d.tlsVersion],
      ['TLS cipher', d.tlsCipher],
      ['User agent', d.userAgent],
    ].filter(([, v]) => v)
      .map(([k, v]) => `<tr><td>${k}</td><td>${window.escapeHtml(v)}</td></tr>`).join('');

    // Cross-links to the deeper tools, pre-filled with the detected IP.
    const q = encodeURIComponent(d.ip);
    const links = '<div class="note">Dig deeper: '
      + `<a href="?q=${q}&tab=whois&sub=main">Whois</a> · `
      + `<a href="?q=${q}&tab=network&sub=asn">ASN details</a> · `
      + `<a href="?q=${q}&tab=network&sub=geo">Geolocation</a> · `
      + `<a href="?q=${q}&tab=network&sub=rdns">Reverse DNS</a> · `
      + `<a href="?q=${q}&tab=email&sub=rbl">Blacklist check</a></div>`;

    panel.innerHTML =
      ipCard
      + window.card('Network', `<table><tbody>${netRows}</tbody></table>`)
      + (connRows ? window.card('Connection', `<table><tbody>${connRows}</tbody></table>`) : '')
      + links
      + '<div class="note">IP, ASN and approximate location are reported by the Cloudflare edge that served this request — no third-party service is queried, and nothing is logged.</div>';
    window.wireCopyButtons(panel);
  } catch (e) {
    window.showError(panel, e.message || 'Could not determine your public IP.');
  }
}

window.registerRunner('myip', 'main', runMyIP);
