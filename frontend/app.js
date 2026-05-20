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

/* ---- Status helper ------------------------------------------------------ */

function setStatus(id, msg, ok) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'status ' + (ok ? 'ok' : 'err');
}

/* ---- API helper --------------------------------------------------------- */

async function apiPost(endpoint, payload) {
  const resp = await fetch(endpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error(e.error || `Server error (${resp.status})`);
  }
  return resp.json();
}

/* ---- Feature detection -------------------------------------------------- */

function checkSupport(statusId) {
  if (!window.PublicKeyCredential) {
    setStatus(statusId, 'Passkeys are not supported in this browser or context.', false);
    return false;
  }
  return true;
}

/* ---- Shared: build assertion payload from a WebAuthn assertion --------- */

function buildAssertionPayload(assertion) {
  return {
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
}

/* ---- Shared: complete an authentication assertion ----------------------- */

async function completeAuth(assertion, statusId) {
  const result = await apiPost('/api/auth/complete', buildAssertionPayload(assertion));
  if (!result.ok) throw new Error(result.error || 'Authentication failed');
  setStatus(statusId, `Logged in as ${result.username}! Token: ${result.token}`, true);
}

/* ---- Conditional UI (autofill) ----------------------------------------- */

let conditionalAbort = null;

async function initConditionalUI() {
  if (!window.PublicKeyCredential) return;

  /* isConditionalMediationAvailable is not available in all browsers */
  const available = await (PublicKeyCredential.isConditionalMediationAvailable?.() ?? false);
  if (!available) return;

  try {
    /* Get a server challenge with no username — returns empty allowCredentials */
    const options = await apiPost('/api/auth/begin', {});
    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    conditionalAbort = new AbortController();

    /* This promise is long-lived: it resolves only when the user selects a
       passkey from the browser autofill dropdown on the username input field. */
    const assertion = await navigator.credentials.get({
      publicKey: options,
      mediation: 'conditional',
      signal:    conditionalAbort.signal,
    });

    await completeAuth(assertion, 'auth-status');
  } catch (e) {
    /* AbortError is expected when the button flow takes over — ignore it */
    if (e.name !== 'AbortError') {
      setStatus('auth-status', 'Error: ' + e.message, false);
    }
  }
}

/* ---- Registration ------------------------------------------------------- */

document.getElementById('reg-btn').addEventListener('click', async () => {
  if (!checkSupport('reg-status')) return;

  const username = document.getElementById('reg-username').value.trim();
  if (!username) { setStatus('reg-status', 'Enter a username.', false); return; }

  setStatus('reg-status', 'Starting registration…', true);

  try {
    const options = await apiPost('/api/register/begin', { username });

    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id   = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    const cred = await navigator.credentials.create({ publicKey: options });

    const payload = {
      id:    cred.id,
      rawId: bufferToBase64url(cred.rawId),
      type:  cred.type,
      response: {
        attestationObject: bufferToBase64url(cred.response.attestationObject),
        clientDataJSON:    bufferToBase64url(cred.response.clientDataJSON),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    };

    const result = await apiPost('/api/register/complete', payload);
    if (!result.ok) throw new Error(result.error || 'Registration failed');

    setStatus('reg-status', 'Passkey registered! You can now log in.', true);
  } catch (e) {
    setStatus('reg-status', 'Error: ' + e.message, false);
  }
});

/* ---- Authentication (button-initiated) ---------------------------------- */

document.getElementById('auth-btn').addEventListener('click', async () => {
  if (!checkSupport('auth-status')) return;

  /* Abort any in-flight conditional request before starting our own */
  conditionalAbort?.abort();
  conditionalAbort = null;

  const username = document.getElementById('auth-username').value.trim();
  setStatus('auth-status', 'Starting authentication…', true);

  try {
    /* Send username if provided (named flow); omit for immediate discoverable modal */
    const options = await apiPost('/api/auth/begin', username ? { username } : {});

    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    const assertion = await navigator.credentials.get({ publicKey: options });
    await completeAuth(assertion, 'auth-status');
  } catch (e) {
    setStatus('auth-status', 'Error: ' + e.message, false);
  }
});

/* ---- Boot --------------------------------------------------------------- */

initConditionalUI();
