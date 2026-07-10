// app.js — tab routing, input handling, shared utils

// ---- Which tabs use the shared input bar (Utils does not) ----
const SHARED_INPUT_TABS = new Set(['dns', 'email', 'web', 'network', 'cert', 'whois', 'm365', 'cloud']);

// Subtabs that live under a shared-input tab but are self-contained (need no query).
const NO_QUERY_SUBTABS = new Set(['email:headers', 'email:builder', 'network:subnet', 'network:cidr', 'cloud:arn', 'cert:decode']);

// Default subtab per tab (matches the .active markup in index.html)
const DEFAULT_SUBTAB = {
  dns: 'lookup',
  email: 'spf',
  web: 'httpheaders',
  network: 'asn',
  cert: 'lookup',
  whois: 'main',
  m365: 'main',
  cloud: 'ip',
  password: 'main',
  utils: 'base64',
};

// Registry: which run function handles each (tab, subtab). Modules register here.
// key = `${tab}:${subtab}` -> async function(query, panelEl)
const RUNNERS = {};
function registerRunner(tab, subtab, fn) {
  RUNNERS[`${tab}:${subtab}`] = fn;
}
window.registerRunner = registerRunner;

let state = { tab: 'dns', sub: 'lookup', q: '' };
// Remember the last query each (tab:sub) actually ran with, so we don't re-run needlessly.
const lastRan = {};

// ---- URL params ----
function getParams() {
  const p = new URLSearchParams(location.search);
  return {
    q: p.get('q') || '',
    tab: p.get('tab') || 'dns',
    sub: p.get('sub') || '',
  };
}

function setParams(q, tab, sub) {
  const p = new URLSearchParams();
  if (q) p.set('q', q);
  if (tab) p.set('tab', tab);
  if (sub) p.set('sub', sub);
  const url = `${location.pathname}?${p.toString()}`;
  history.pushState({ q, tab, sub }, '', url);
}

// ---- Panel element helper ----
function panelEl(tab, sub) {
  return document.getElementById(`panel-${tab}-${sub}`);
}

// ---- UI helpers ----
function showLoading(panel, label = 'Working…') {
  if (!panel) return;
  panel.innerHTML = `<div class="loading"><span class="spinner"></span>${escapeHtml(label)}</div>`;
}
function showError(panel, message) {
  if (!panel) return;
  panel.innerHTML = `<div class="summary red">${escapeHtml(message)}</div>`;
}
function showResult(panel, html) {
  if (!panel) return;
  panel.innerHTML = html;
  wireCopyButtons(panel);
}

function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// A card with an optional copy button targeting given text
function card(title, bodyHtml, copyText) {
  const copy = copyText != null
    ? `<button class="copy-btn" data-copy="${escapeHtml(copyText)}">copy</button>`
    : '';
  const h = title ? `<h3>${escapeHtml(title)}</h3>` : '';
  return `<div class="card">${copy}${h}${bodyHtml}</div>`;
}

function wireCopyButtons(root) {
  root.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      copyToClipboard(btn.getAttribute('data-copy'));
      const orig = btn.textContent;
      btn.textContent = btn.classList.contains('copy-cell') ? '✓' : 'copied';
      setTimeout(() => { btn.textContent = orig; }, 1200);
    });
  });
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}
function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) { /* ignore */ }
  document.body.removeChild(ta);
}

// ---- Input validation ----
// The pure validators (isIP, isIPv4, isIPv6, isDomain, isCIDR, isASN, isURL,
// normalizeURL) come from core.js, which loads first and attaches them to the
// global scope. This keeps a single source of truth shared with the test suite.
function hostFromInput(str) {
  str = (str || '').trim();
  if (isIP(str) || isDomain(str)) return str;
  try { return new URL(normalizeURL(str)).hostname; } catch (e) { return str; }
}

// ---- Shared DNS resolution ----
// Try public DoH straight from the browser first (free — no Worker invocation),
// and only fall back to our own edge (/api/dns) when that's blocked. Corporate
// and captive networks routinely block cloudflare-dns.com et al.; the fallback
// keeps every DNS-backed tool working there while the common case costs us
// nothing. These endpoints speak DoH-JSON with permissive CORS — keys match
// /api/dns's ?resolver= values.
const DOH_DIRECT = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/resolve',
  dnssb: 'https://doh.sb/dns-query',
};
// Per-session memo: once the default resolver proves unreachable (a real network
// block, not a per-record error), stop paying the failed-fetch latency on every
// lookup and go straight to the backend for the rest of the session.
let dohDirectBlocked = false;

async function dohQuery(name, type, resolver = 'cloudflare') {
  const base = !dohDirectBlocked && DOH_DIRECT[resolver];
  if (base) {
    try {
      const sep = base.includes('?') ? '&' : '?';
      const url = `${base}${sep}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
      // Bound the attempt so a black-holing firewall can't hang the first lookup.
      const res = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(3500) });
      if (res.ok) {
        const data = await res.json();
        // Guard against captive portals that answer 200 with non-DNS HTML/JSON:
        // a real DoH reply always carries a numeric Status.
        if (data && typeof data.Status === 'number') return data;
      }
    } catch (e) {
      // Network error / CORS / TLS / timeout — treat a failure of the default
      // resolver as this network blocking direct DoH for the whole session.
      if (resolver === 'cloudflare') dohDirectBlocked = true;
    }
  }
  // Server-side fallback: DoH from the Cloudflare edge, same-origin.
  const url = `/api/dns?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&resolver=${encodeURIComponent(resolver)}`;
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`DNS query failed (${res.status})`);
  return res.json();
}

async function resolveToIP(hostname) {
  if (isIP(hostname)) return hostname;
  const data = await dohQuery(hostname, 'A');
  const answer = (data.Answer || []).find((a) => a.type === 1);
  if (!answer) throw new Error(`Could not resolve ${hostname} to an IP address.`);
  return answer.data;
}

// Expose shared helpers to modules. Validators are already global (core.js);
// re-export the ones some modules reference via the window.* namespace.
Object.assign(window, {
  getParams, setParams, panelEl,
  showLoading, showError, showResult,
  escapeHtml, card, copyToClipboard, wireCopyButtons,
  hostFromInput,
  dohQuery, resolveToIP,
});

// ---- Tab / subtab switching ----
function setActiveTab(tab) {
  document.querySelectorAll('.tabs.primary .tab').forEach((el) => {
    el.classList.toggle('active', el.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-panel').forEach((el) => {
    el.classList.toggle('active', el.id === `tab-${tab}`);
  });
  // Show/hide shared input bar
  const bar = document.getElementById('input-bar');
  if (SHARED_INPUT_TABS.has(tab)) bar.classList.remove('hidden');
  else bar.classList.add('hidden');
}

function setActiveSubtab(tab, sub) {
  const panel = document.getElementById(`tab-${tab}`);
  if (!panel) return;
  panel.querySelectorAll('.subtab').forEach((el) => {
    el.classList.toggle('active', el.dataset.subtab === sub);
  });
  panel.querySelectorAll('.subpanel').forEach((el) => {
    el.classList.toggle('active', el.id === `panel-${tab}-${sub}`);
  });
}

// Run the active (tab, sub) if its query changed or it has never run.
function maybeRun(force = false) {
  const { tab, sub, q } = state;
  const key = `${tab}:${sub}`;
  const runner = RUNNERS[key];
  if (!runner) return;

  // Utils runners are self-contained and set themselves up on activation.
  const needsQuery = SHARED_INPUT_TABS.has(tab) && !NO_QUERY_SUBTABS.has(key);
  if (needsQuery && !q) {
    // Prompt for input rather than erroring on first load.
    const p = panelEl(tab, sub);
    if (p && !p.dataset.rendered) {
      p.innerHTML = `<div class="note">Enter a ${tab === 'web' ? 'URL' : 'domain, hostname, or IP'} above and press Run.</div>`;
    }
    return;
  }

  if (!force && lastRan[key] === q && needsQuery) return;
  lastRan[key] = q;
  const p = panelEl(tab, sub);
  if (p) p.dataset.rendered = '1';
  Promise.resolve(runner(q, p)).catch((err) => {
    showError(p, err && err.message ? err.message : 'Something went wrong.');
  });
}

function activate(tab, sub, { pushUrl = true, force = false } = {}) {
  // Validate against the DOM so a stale/hand-edited URL (?tab=bogus, or a sub
  // that belongs to another tab) can't leave the page blank — fall back instead.
  if (!document.getElementById(`tab-${tab}`)) tab = 'dns';
  sub = sub || DEFAULT_SUBTAB[tab] || '';
  if (!document.getElementById(`panel-${tab}-${sub}`)) sub = DEFAULT_SUBTAB[tab] || sub;
  state.tab = tab;
  state.sub = sub;
  setActiveTab(tab);
  setActiveSubtab(tab, sub);
  if (pushUrl) setParams(state.q, tab, sub);
  maybeRun(force);
}

function readInput() {
  const val = document.getElementById('query').value.trim();
  state.q = val;
  return val;
}

function clearInputError() {
  const el = document.getElementById('input-error');
  el.hidden = true;
  el.textContent = '';
}
function setInputError(msg) {
  const el = document.getElementById('input-error');
  el.hidden = false;
  el.textContent = msg;
}

function runFromInput() {
  clearInputError();
  readInput();
  setParams(state.q, state.tab, state.sub);
  maybeRun(true);
}

// ---- Wire up events ----
function init() {
  // Primary tabs
  document.querySelectorAll('.tabs.primary .tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      readInput();
      activate(btn.dataset.tab);
    });
  });
  // Subtabs (delegated per tab-panel)
  document.querySelectorAll('.tab-panel').forEach((panel) => {
    const tab = panel.id.replace('tab-', '');
    panel.querySelectorAll('.subtab').forEach((btn) => {
      btn.addEventListener('click', () => {
        readInput();
        activate(tab, btn.dataset.subtab);
      });
    });
  });

  // Input bar
  document.getElementById('run-btn').addEventListener('click', runFromInput);
  document.getElementById('query').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); runFromInput(); }
  });

  // Back/forward
  window.addEventListener('popstate', () => {
    const { q, tab, sub } = getParams();
    document.getElementById('query').value = q;
    state.q = q;
    activate(tab, sub, { pushUrl: false });
  });

  // Initial state from URL
  const { q, tab, sub } = getParams();
  document.getElementById('query').value = q;
  state.q = q;
  activate(tab, sub, { pushUrl: false, force: !!q });
}

document.addEventListener('DOMContentLoaded', init);
