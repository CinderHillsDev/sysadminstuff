// m365.js — Microsoft 365 / Entra ID tenant lookup (via /api/tenant)

const ENV_BADGE = {
  'Commercial': 'blue',
  'GCC': 'yellow',
  'GCC High': 'green',
  'DoD': 'red',
};

async function runTenant(query, panel) {
  const domain = window.hostFromInput(query);
  if (!window.isDomain(domain)) { window.showError(panel, 'Enter a domain (e.g. contoso.com).'); return; }
  window.showLoading(panel, `Looking up the Microsoft tenant for ${domain}…`);
  try {
    const res = await fetch(`/api/tenant?domain=${encodeURIComponent(domain)}`);
    if (!res.ok) {
      let msg = `Tenant lookup failed (${res.status})`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    const d = await res.json();
    if (!d.isTenant) {
      panel.innerHTML = `<div class="summary grey">No Microsoft 365 / Entra tenant found for ${window.escapeHtml(d.domain || domain)}.</div>`;
      return;
    }

    const badge = ENV_BADGE[d.environment] || 'grey';
    const isGov = d.cloudInstance === 'microsoftonline.us';
    const summary = `<div class="summary ${badge}">Environment: <span class="badge ${badge}">${window.escapeHtml(d.environment)}</span>` +
      (isGov ? ' &nbsp;·&nbsp; US Government cloud' : '') +
      `<br><span class="muted">${window.escapeHtml(d.brandName || d.domain)}</span></div>`;

    const nsBadge = d.namespaceType === 'Federated' ? 'yellow' : (d.namespaceType === 'Managed' ? 'green' : 'grey');
    const rows = [
      ['Tenant ID', d.tenantId ? `<code>${window.escapeHtml(d.tenantId)}</code>` : '—'],
      ['Brand name', window.escapeHtml(d.brandName || '—')],
      ['Identity', d.namespaceType ? `<span class="badge ${nsBadge}">${window.escapeHtml(d.namespaceType)}</span>${d.namespaceType === 'Federated' ? ' (ADFS / external IdP)' : d.namespaceType === 'Managed' ? ' (Entra ID / cloud)' : ''}` : '—'],
    ];
    if (d.authUrl) {
      // Only link http(s); an attacker-controlled federated domain could return a
      // javascript:/data: AuthURL (encodeURI does NOT neutralize the scheme).
      const safeUrl = /^https?:\/\//i.test(d.authUrl);
      rows.push(['Federation URL', safeUrl
        ? `<a href="${encodeURI(d.authUrl)}" target="_blank" rel="noopener noreferrer">${window.escapeHtml(d.authUrl)}</a>`
        : window.escapeHtml(d.authUrl)]);
    }
    rows.push(
      ['Cloud instance', window.escapeHtml(d.cloudInstance || '—')],
      ['Region scope', window.escapeHtml(d.regionScope || '—') + (d.subScope ? ` / ${window.escapeHtml(d.subScope)}` : '')],
    );
    const tenantCard = window.card(`Tenant — ${d.domain}`,
      `<table><tbody>${rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('')}</tbody></table>`,
      d.tenantId || undefined);

    let domainsCard = '';
    if (d.domains && d.domains.length) {
      const list = d.domains.map((x) => window.escapeHtml(x)).join('\n');
      domainsCard = window.card(`Tenant domains (${d.domainCount})`,
        `<pre class="raw">${d.domains.map((x) => window.escapeHtml(x)).join('<br>')}</pre>`,
        list);
    }

    window.showResult(panel, summary + tenantCard + domainsCard);
  } catch (e) {
    window.showError(panel, e.message || 'Tenant lookup failed.');
  }
}

window.registerRunner('m365', 'main', runTenant);
