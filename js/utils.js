// utils.js — Base64, URL Encode, JWT Decoder — all client-side, no network.
// b64EncodeUtf8 / b64DecodeUtf8 / looksLikeBase64 / decodeJwtParts come from
// core.js (global scope), so the browser and the tests share one implementation.
const b64EncodeUtf8 = window.b64EncodeUtf8;
const b64DecodeUtf8 = window.b64DecodeUtf8;
const looksLikeBase64 = window.looksLikeBase64;

// ---------- Base64 ----------
function runBase64(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Encoded/decoded entirely in your browser.</div>
    <div class="util-io two-col">
      <div><label class="field-label">Input</label><textarea class="mono" id="b64-in" placeholder="Text or base64…"></textarea></div>
      <div><label class="field-label">Output</label><textarea class="mono" id="b64-out" readonly></textarea></div>
    </div>
    <div class="btn-row">
      <button class="btn" id="b64-encode">Encode →</button>
      <button class="btn" id="b64-decode">Decode →</button>
      <span class="muted" id="b64-msg"></span>
    </div>`;
  const inp = panel.querySelector('#b64-in');
  const out = panel.querySelector('#b64-out');
  const msg = panel.querySelector('#b64-msg');
  const enc = () => { try { out.value = b64EncodeUtf8(inp.value); msg.textContent = ''; } catch (e) { msg.textContent = 'Encode error.'; } };
  const dec = () => { try { out.value = b64DecodeUtf8(inp.value); msg.textContent = ''; } catch (e) { out.value = ''; msg.textContent = 'Not valid base64.'; } };
  panel.querySelector('#b64-encode').addEventListener('click', enc);
  panel.querySelector('#b64-decode').addEventListener('click', dec);
  // Auto-detect on input: if it looks like base64, decode; else encode
  inp.addEventListener('input', () => { looksLikeBase64(inp.value) ? dec() : enc(); });
  panel.dataset.wired = '1';
}

// ---------- URL Encode ----------
function runURLEncode(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Encoded/decoded entirely in your browser.</div>
    <div class="util-io two-col">
      <div><label class="field-label">Input</label><textarea class="mono" id="url-in" placeholder="Text or encoded string…"></textarea></div>
      <div><label class="field-label">Output</label><textarea class="mono" id="url-out" readonly></textarea></div>
    </div>
    <div class="btn-row">
      <button class="btn" id="url-encode">Encode →</button>
      <button class="btn" id="url-decode">Decode →</button>
      <span class="muted" id="url-msg"></span>
    </div>`;
  const inp = panel.querySelector('#url-in');
  const out = panel.querySelector('#url-out');
  const msg = panel.querySelector('#url-msg');
  panel.querySelector('#url-encode').addEventListener('click', () => { out.value = encodeURIComponent(inp.value); msg.textContent = ''; });
  panel.querySelector('#url-decode').addEventListener('click', () => { try { out.value = decodeURIComponent(inp.value); msg.textContent = ''; } catch (e) { out.value = ''; msg.textContent = 'Not a valid encoded string.'; } });
  panel.dataset.wired = '1';
}

// ---------- JWT Decoder ----------
function runJWT(query, panel) {
  if (panel.dataset.wired) return;
  panel.innerHTML = `
    <div class="privacy-note">Decoded entirely in your browser. Your token is never sent to our servers or anywhere else.</div>
    <textarea class="mono" id="jwt-in" placeholder="Paste a JWT (eyJ...)…"></textarea>
    <div class="result" id="jwt-out"></div>`;
  const inp = panel.querySelector('#jwt-in');
  const out = panel.querySelector('#jwt-out');
  inp.addEventListener('input', () => decodeJWT(inp.value, out));
  panel.dataset.wired = '1';
}

function decodeJWT(token, out) {
  token = token.trim();
  if (!token) { out.innerHTML = ''; return; }
  const res = window.decodeJwtParts(token);
  if (!res.ok) {
    if (res.error && res.error.startsWith('expected 3 parts')) {
      out.innerHTML = `<div class="summary grey">A JWT has three dot-separated parts. ${window.escapeHtml(res.error)}.</div>`;
    } else if (res.error === 'bad header') {
      out.innerHTML = `<div class="summary red">Header is not valid base64url JSON.</div>`;
    } else if (res.error === 'bad payload') {
      out.innerHTML = `<div class="summary red">Payload is not valid base64url JSON.</div>`;
    } else {
      out.innerHTML = '';
    }
    return;
  }
  const { header, payload } = res;
  const parts = [null, null, res.signature];

  let expNote = '';
  if (payload.exp) {
    const expDate = new Date(payload.exp * 1000);
    const expired = expDate < new Date();
    expNote = `<div class="summary ${expired ? 'red' : 'green'}">exp: ${expDate.toISOString()} — ${expired ? 'EXPIRED' : 'valid'}</div>`;
  }
  const headerJson = JSON.stringify(header, null, 2);
  const payloadJson = JSON.stringify(payload, null, 2);
  out.innerHTML =
    expNote +
    window.card('Header', `<pre class="raw">${window.escapeHtml(headerJson)}</pre>`, headerJson) +
    window.card('Payload', `<pre class="raw">${window.escapeHtml(payloadJson)}</pre>`, payloadJson) +
    window.card('Signature', `<pre class="raw">${window.escapeHtml(parts[2])}</pre><div class="note">Verification requires the signing secret/public key and is not performed here.</div>`, parts[2]);
  // wire copy buttons injected here
  out.querySelectorAll('.copy-btn[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => { window.copyToClipboard(btn.getAttribute('data-copy')); const o = btn.textContent; btn.textContent = 'copied'; setTimeout(() => btn.textContent = o, 1200); });
  });
}

window.registerRunner('utils', 'base64', runBase64);
window.registerRunner('utils', 'urlencode', runURLEncode);
window.registerRunner('utils', 'jwt', runJWT);
