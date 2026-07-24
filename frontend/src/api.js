/**
 * All backend calls go through here, always as relative paths: the Vite dev
 * server proxies them to the backend so the browser never leaves this origin.
 * The session cookie is same-origin only — an absolute backend URL here would
 * silently break authentication.
 */
export async function api(path, body) {
  const r = await fetch(path, {
    method: body !== undefined ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(j.detail || `request failed (${r.status})`)
  return j
}
