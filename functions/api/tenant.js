// functions/api/tenant.js — Microsoft 365 / Entra ID tenant lookup using public,
// unauthenticated Microsoft endpoints. No login, no API key. No user input logged.
//
// Sources:
//   - OpenID Connect metadata  -> tenant GUID, region + sub-scope, cloud instance
//   - GetUserRealm             -> brand name, Managed/Federated (ADFS) status
//   - GetFederationInformation -> other domains in the same tenant (best-effort)

import { classifyTenantEnvironment, extractTenantId, parseTenantDomains } from '../../lib/parse.mjs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  let domain = (new URL(request.url).searchParams.get('domain') || '').trim().toLowerCase();
  if (domain.includes('@')) domain = domain.split('@').pop();       // accept an email too
  if (!domain) return json({ error: 'Missing domain parameter.' }, 400);
  if (!/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(domain)) {
    return json({ error: 'Enter a valid domain.' }, 400);
  }

  // 1. OIDC metadata — authoritative for tenant id + cloud environment.
  let oidc;
  try {
    const res = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(domain)}/v2.0/.well-known/openid-configuration`);
    oidc = await res.json();
  } catch (e) {
    console.error('OIDC fetch failed.');
    return json({ error: 'Could not reach Microsoft. Try again shortly.' }, 502);
  }
  if (!oidc || oidc.error || !oidc.issuer) {
    return json({ domain, isTenant: false });
  }

  const tenantId = extractTenantId(oidc.issuer);
  const regionScope = oidc.tenant_region_scope || '';
  const subScope = oidc.tenant_region_sub_scope || '';
  const cloudInstance = oidc.cloud_instance_name || '';
  const environment = classifyTenantEnvironment({ subScope, cloudInstance });

  // US Gov cloud tenants (GCC High / DoD) live on the *.us endpoints; using the
  // commercial hosts for them returns nothing.
  const gov = cloudInstance === 'microsoftonline.us';
  const loginHost = gov ? 'login.microsoftonline.us' : 'login.microsoftonline.com';
  const autodiscoverHost = gov ? 'autodiscover-s.office365.us' : 'autodiscover-s.outlook.com';

  // 2. GetUserRealm — brand name + Managed/Federated (ADFS). Best-effort.
  let brandName = '', namespaceType = '', authUrl = '';
  try {
    const res = await fetch(`https://${loginHost}/getuserrealm.srf?login=${encodeURIComponent('user@' + domain)}&json=1`);
    if (res.ok) {
      const g = await res.json();
      brandName = g.FederationBrandName || '';
      namespaceType = g.NameSpaceType || '';
      authUrl = g.AuthURL || '';
    }
  } catch (e) { /* best-effort */ }

  // 3. Other domains in the tenant via Autodiscover SOAP. Best-effort.
  let domains = [];
  try { domains = await getTenantDomains(domain, autodiscoverHost); } catch (e) { /* best-effort */ }

  return json({
    domain,
    isTenant: true,
    tenantId,
    brandName,
    namespaceType,        // Managed | Federated
    authUrl,              // ADFS endpoint when Federated
    environment,          // Commercial | GCC | GCC High | DoD | ...
    regionScope,
    subScope,
    cloudInstance,
    domains,
    domainCount: domains.length,
  });
}

async function getTenantDomains(domain, host) {
  const endpoint = `https://${host}/autodiscover/autodiscover.svc`;
  const body = `<?xml version="1.0" encoding="utf-8"?>` +
    `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:wsa="http://www.w3.org/2005/08/addressing">` +
    `<soap:Header>` +
    `<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>` +
    `<a:To soap:mustUnderstand="1">${endpoint}</a:To>` +
    `<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>` +
    `</soap:Header>` +
    `<soap:Body><GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">` +
    `<Request><Domain>${domain.replace(/[<>&]/g, '')}</Domain></Request>` +
    `</GetFederationInformationRequestMessage></soap:Body></soap:Envelope>`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      SOAPAction: '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
      'User-Agent': 'AutodiscoverClient',
    },
    body,
  });
  if (!res.ok) return [];
  return parseTenantDomains(await res.text());
}
