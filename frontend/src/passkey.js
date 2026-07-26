/**
 * WebAuthn passkeys — the R2 return-login.
 *
 * Fayda establishes the identity once; a passkey brings the same person back
 * with device biometric instead of the full national-ID flow. The private key
 * stays in the authenticator, so there is nothing here to steal and nothing to
 * phish: the browser refuses to sign for an origin the credential was not
 * created on.
 *
 * The server speaks base64url (JSON has no byte type) and the WebAuthn API
 * speaks ArrayBuffer, so this module is mostly that translation, kept in one
 * place so no component has to know about it.
 */

const b64uToBytes = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4))
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0))
}

const bytesToB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

/** Whether this browser can do platform (biometric) passkeys at all. */
export function passkeysSupported() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential
}

async function post(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(j.detail || `Passkey step failed (${r.status}).`)
  return j
}

/**
 * Register a passkey for the already Fayda-verified session. Throws with a
 * human-readable message; the caller decides how to show it.
 */
export async function registerPasskey(label) {
  const opts = await post('/api/passkey/register/begin')
  opts.challenge = b64uToBytes(opts.challenge)
  opts.user.id = b64uToBytes(opts.user.id)
  opts.excludeCredentials = (opts.excludeCredentials || []).map((c) => ({
    ...c,
    id: b64uToBytes(c.id),
  }))

  const cred = await navigator.credentials.create({ publicKey: opts })
  if (!cred) throw new Error('No passkey was created.')

  return post('/api/passkey/register/complete', {
    label,
    credential: {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        attestationObject: bytesToB64u(cred.response.attestationObject),
      },
    },
  })
}

/** Sign in with a previously registered passkey. No Fayda round trip. */
export async function loginWithPasskey() {
  const opts = await post('/api/passkey/login/begin')
  opts.challenge = b64uToBytes(opts.challenge)
  opts.allowCredentials = (opts.allowCredentials || []).map((c) => ({
    ...c,
    id: b64uToBytes(c.id),
  }))

  const cred = await navigator.credentials.get({ publicKey: opts })
  if (!cred) throw new Error('No passkey was offered.')

  return post('/api/passkey/login/complete', {
    credential: {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        authenticatorData: bytesToB64u(cred.response.authenticatorData),
        signature: bytesToB64u(cred.response.signature),
        userHandle: cred.response.userHandle
          ? bytesToB64u(cred.response.userHandle)
          : null,
      },
    },
  })
}
