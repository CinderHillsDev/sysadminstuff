// cloud.js — cloud-focused tools: IP→provider, hosting fingerprint, AWS key→account, ARN parser.

// ---------- Cloud IP (which cloud + region) ----------
let awsRangesCache = null;
async function loadAwsRanges() {
  if (awsRangesCache) return awsRangesCache;
  const res = await fetch('https://ip-ranges.amazonaws.com/ip-ranges.json');
  if (!res.ok) throw new Error('Could not load AWS IP ranges.');
  awsRangesCache = await res.json();
  return awsRangesCache;
}
function ipv4InCidr(ip, cidr) {
  const [net, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  if (!window.isIPv4(ip) || !window.isIPv4(net)) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((window.ipToInt(ip) & mask) >>> 0) === ((window.ipToInt(net) & mask) >>> 0);
}
async function runCloudIP(query, panel) {
  window.showLoading(panel, 'Resolving…');
  try {
    const ip = await window.resolveToIP(window.hostFromInput(query));
    if (window.isPrivateIP(ip)) { window.showError(panel, `${ip} is a private/reserved address (RFC1918).`); return; }
    window.showLoading(panel, `Identifying the cloud for ${ip}…`);

    // 1. AWS — exact match against the official ranges (region + service).
    let awsMatches = [];
    try {
      const aws = await loadAwsRanges();
      awsMatches = (aws.prefixes || []).filter((p) => p.ip_prefix && ipv4InCidr(ip, p.ip_prefix));
    } catch (e) { /* fall through to ASN */ }

    if (awsMatches.length) {
      const region = awsMatches[0].region;
      const services = [...new Set(awsMatches.map((p) => p.service))].sort();
      const prefixes = [...new Set(awsMatches.map((p) => p.ip_prefix))];
      window.showResult(panel,
        `<div class="summary yellow">Provider: <span class="badge yellow">Amazon Web Services</span> &nbsp;·&nbsp; region <strong>${window.escapeHtml(region)}</strong></div>` +
        window.card(`AWS — ${ip}`, '<table><tbody>' +
          `<tr><td>Region</td><td>${window.escapeHtml(region)}</td></tr>` +
          `<tr><td>Services</td><td>${window.escapeHtml(services.join(', '))}</td></tr>` +
          `<tr><td>Matched prefix</td><td class="data-cell"><span class="data-val">${window.escapeHtml(prefixes.join(', '))}</span></td></tr>` +
          '</tbody></table>'));
      return;
    }

    // 2. Everything else — classify by ASN org from ipwho.is.
    const geo = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`).then((r) => r.json()).catch(() => null);
    const conn = (geo && geo.connection) || {};
    const provider = window.classifyCloudOrg(conn.org || conn.isp || '');
    const badge = provider ? 'yellow' : 'grey';
    window.showResult(panel,
      `<div class="summary ${badge}">Provider: <span class="badge ${badge}">${window.escapeHtml(provider || 'Not a recognized cloud')}</span></div>` +
      window.card(`IP — ${ip}`, '<table><tbody>' +
        `<tr><td>Organization</td><td>${window.escapeHtml(conn.org || '—')}</td></tr>` +
        `<tr><td>ISP</td><td>${window.escapeHtml(conn.isp || '—')}</td></tr>` +
        `<tr><td>ASN</td><td>${conn.asn ? 'AS' + window.escapeHtml(String(conn.asn)) : '—'}</td></tr>` +
        `<tr><td>Location</td><td>${window.escapeHtml([geo && geo.city, geo && geo.country].filter(Boolean).join(', ') || '—')}</td></tr>` +
        '</tbody></table>'));
  } catch (e) {
    window.showError(panel, e.message || 'Cloud IP lookup failed.');
  }
}

// ---------- Hosting fingerprint (CDN / email / DNS provider) ----------
async function runFingerprint(query, panel) {
  const domain = window.hostFromInput(query);
  if (!window.isDomain(domain)) { window.showError(panel, 'Enter a domain (e.g. example.com).'); return; }
  window.showLoading(panel, `Fingerprinting ${domain}…`);
  try {
    const dq = (t) => window.dohQuery(domain, t).then((d) => d.Answer || []).catch(() => []);
    const [cname, mx, ns, a] = await Promise.all([dq('CNAME'), dq('MX'), dq('NS'), dq('A')]);

    const cnameTargets = cname.filter((x) => x.type === 5).map((x) => x.data.replace(/\.$/, ''));
    const mxHosts = mx.filter((x) => x.type === 15).map((x) => x.data.split(/\s+/).pop().replace(/\.$/, ''));
    const nsHosts = ns.filter((x) => x.type === 2).map((x) => x.data.replace(/\.$/, ''));

    const firstProvider = (hosts) => { for (const h of hosts) { const p = window.matchProvider(h); if (p) return p; } return null; };

    let hosting = firstProvider(cnameTargets);
    // No CNAME hint? Classify the A-record IP's owner as the hosting cloud.
    if (!hosting && a.some((x) => x.type === 1)) {
      const ip = a.find((x) => x.type === 1).data;
      const geo = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`).then((r) => r.json()).catch(() => null);
      hosting = window.classifyCloudOrg((geo && geo.connection && (geo.connection.org || geo.connection.isp)) || '');
    }
    const email = firstProvider(mxHosts);
    const dns = firstProvider(nsHosts);

    const row = (label, val, detail) => `<tr><td>${label}</td><td>${val ? `<span class="badge blue">${window.escapeHtml(val)}</span>` : '<span class="muted">unknown</span>'}${detail ? `<br><span class="muted">${window.escapeHtml(detail)}</span>` : ''}</td></tr>`;
    window.showResult(panel,
      window.card(`What ${domain} runs on`, '<table><tbody>' +
        row('Hosting / CDN', hosting, cnameTargets.join(', ')) +
        row('Email', email, mxHosts.join(', ')) +
        row('DNS', dns, nsHosts.join(', ')) +
        '</tbody></table>') +
      '<div class="note">Inferred from CNAME, MX, and NS records. "Unknown" just means no known pattern matched.</div>');
  } catch (e) {
    window.showError(panel, e.message || 'Fingerprint failed.');
  }
}

// ---------- ARN parser ----------
function runArn(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Parsed in your browser.</div>
    <div class="btn-row">
      <input class="text-input" id="arn-in" placeholder="arn:aws:iam::123456789012:role/MyRole" style="flex:1;min-width:20rem">
      <button class="btn primary" id="arn-go">Parse</button>
    </div>
    <div class="result" id="arn-out"></div>`;
  const out = panel.querySelector('#arn-out');
  const go = () => {
    const a = window.parseArn(panel.querySelector('#arn-in').value);
    if (!a) { window.showError(out, 'Enter a valid ARN (arn:partition:service:region:account:resource).'); return; }
    const rows = [
      ['Partition', a.partition], ['Service', a.service], ['Region', a.region],
      ['Account ID', a.account], ['Resource', a.resource],
    ].map(([k, v]) => `<tr><td>${k}</td><td class="data-cell"><span class="data-val">${window.escapeHtml(v)}</span><button class="copy-cell" data-copy="${window.escapeHtml(v)}" title="Copy">⧉</button></td></tr>`).join('');
    out.innerHTML = window.card('ARN components', `<table><tbody>${rows}</tbody></table>`);
    window.wireCopyButtons(out);
  };
  panel.querySelector('#arn-go').addEventListener('click', go);
  panel.querySelector('#arn-in').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  panel.dataset.wired = '1';
}

window.registerRunner('cloud', 'ip', runCloudIP);
window.registerRunner('cloud', 'fingerprint', runFingerprint);
window.registerRunner('cloud', 'arn', runArn);
