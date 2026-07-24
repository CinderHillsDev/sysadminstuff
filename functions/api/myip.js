// functions/api/myip.js — reflect the caller's own public IP and the network
// metadata Cloudflare already knows about it (ASN, org, geo, edge colo, TLS).
// Everything here comes from the edge for free: the CF-Connecting-IP header and
// request.cf. No upstream call, and — per PRIVACY.md — nothing is logged.

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

  const cf = request.cf || {};
  const ip = request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Real-IP')
    || '';

  return json({
    ip,
    asn: cf.asn != null ? Number(cf.asn) : null,
    org: cf.asOrganization || null,
    country: cf.country || null,
    region: cf.region || null,
    regionCode: cf.regionCode || null,
    city: cf.city || null,
    postalCode: cf.postalCode || null,
    latitude: cf.latitude || null,
    longitude: cf.longitude || null,
    timezone: cf.timezone || null,
    continent: cf.continent || null,
    // Edge / connection facts about how this request reached Cloudflare.
    colo: cf.colo || null,
    httpProtocol: cf.httpProtocol || null,
    tlsVersion: cf.tlsVersion || null,
    tlsCipher: cf.tlsCipher || null,
    userAgent: request.headers.get('User-Agent') || null,
  });
}
