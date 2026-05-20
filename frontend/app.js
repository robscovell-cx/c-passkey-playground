'use strict';

/* ---- Base64url helpers -------------------------------------------------- */

function bufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBuffer(b64) {
  const pad = b64.length % 4 === 0 ? '' : '===='.slice(b64.length % 4);
  const std = b64.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(std);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

/* ---- Status helpers ----------------------------------------------------- */

function setStatus(id, msg, ok) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'status ' + (ok ? 'ok' : 'err');
}

/* ---- Registration ------------------------------------------------------- */

document.getElementById('reg-btn').addEventListener('click', async () => {
  const username = document.getElementById('reg-username').value.trim();
  if (!username) { setStatus('reg-status', 'Enter a username.', false); return; }

  setStatus('reg-status', 'Starting registration…', true);

  try {
    /* 1. Begin — get options from server */
    const beginResp = await fetch('/api/register/begin', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username }),
    });
    if (!beginResp.ok) {
      const e = await beginResp.json().catch(() => ({}));
      throw new Error(e.error || 'Server error during begin');
    }
    const options = await beginResp.json();

    /* 2. Transform: decode base64url fields to ArrayBuffer */
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id   = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    /* 3. Browser WebAuthn API */
    const cred = await navigator.credentials.create({ publicKey: options });

    /* 4. Serialize response buffers to base64url */
    const payload = {
      id:    cred.id,
      rawId: bufferToBase64url(cred.rawId),
      type:  cred.type,
      response: {
        attestationObject: bufferToBase64url(cred.response.attestationObject),
        clientDataJSON:    bufferToBase64url(cred.response.clientDataJSON),
      },
    };

    /* 5. Complete — send to server */
    const completeResp = await fetch('/api/register/complete', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    const result = await completeResp.json();
    if (!result.ok) throw new Error(result.error || 'Registration failed');

    setStatus('reg-status', 'Passkey registered! You can now log in.', true);
  } catch (e) {
    setStatus('reg-status', 'Error: ' + e.message, false);
  }
});

/* ---- Authentication ----------------------------------------------------- */

document.getElementById('auth-btn').addEventListener('click', async () => {
  const username = document.getElementById('auth-username').value.trim();
  if (!username) { setStatus('auth-status', 'Enter a username.', false); return; }

  setStatus('auth-status', 'Starting authentication…', true);

  try {
    /* 1. Begin */
    const beginResp = await fetch('/api/auth/begin', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username }),
    });
    if (!beginResp.ok) {
      const e = await beginResp.json().catch(() => ({}));
      throw new Error(e.error || 'Server error during begin');
    }
    const options = await beginResp.json();

    /* 2. Transform */
    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    /* 3. Browser API */
    const assertion = await navigator.credentials.get({ publicKey: options });

    /* 4. Serialize */
    const payload = {
      id:    assertion.id,
      rawId: bufferToBase64url(assertion.rawId),
      type:  assertion.type,
      response: {
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        clientDataJSON:    bufferToBase64url(assertion.response.clientDataJSON),
        signature:         bufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? bufferToBase64url(assertion.response.userHandle) : null,
      },
    };

    /* 5. Complete */
    const completeResp = await fetch('/api/auth/complete', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    const result = await completeResp.json();
    if (!result.ok) throw new Error(result.error || 'Authentication failed');

    setStatus('auth-status',
      `Logged in as ${result.username}! Token: ${result.token}`, true);
  } catch (e) {
    setStatus('auth-status', 'Error: ' + e.message, false);
  }
});
