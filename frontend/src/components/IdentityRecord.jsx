import { Card } from './ui/card.jsx'
import { Button } from './ui/button.jsx'
import { Badge } from './ui/badge.jsx'
import { CopyValue } from './CopyValue.jsx'

/**
 * The signature element: the verified identity presented as an issued record.
 * residenceStatus is a first-class field — it is the citizenship signal this
 * product hinges on — displayed verbatim and never branched on (value set
 * unconfirmed with NIDP).
 */
export function IdentityRecord({
  me, onLogout, busy, onAddPasskey, onRevokePasskey, passkeys,
}) {
  // A passkey proves control of a registered device, not a fresh national-ID
  // check, so the record says which one established this session rather than
  // implying Fayda just verified the person again.
  const viaPasskey = me.auth_method === 'passkey'
  const id = me.identity
  const claims = me.claims || {}
  return (
    <Card className="border-verify/30 p-0 overflow-hidden">
      <div className="flex items-start justify-between gap-4 border-b border-rule bg-verify-soft/50 px-5 py-3">
        <div className="doc-label !text-verify-ink">Verified identity record</div>
        <Badge status="active">Fayda verified</Badge>
      </div>
      <div className="px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="font-display text-[1.375rem] font-bold leading-snug">
              {id.display_name}
            </div>
            <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
              <dt className="doc-label pt-0.5">Born</dt>
              <dd className="font-mono text-[0.8125rem]">{id.birthdate || '—'}</dd>
              <dt className="doc-label pt-0.5">Residence status</dt>
              <dd>
                <span className="font-mono text-[0.8125rem] font-medium">
                  {claims.residenceStatus || 'not stated'}
                </span>
                <span className="block text-[0.75rem] text-muted">
                  Reported by Fayda. Residency is not citizenship — some valid
                  Fayda holders are foreign nationals.
                </span>
              </dd>
              {claims.address?.region && (
                <>
                  <dt className="doc-label pt-0.5">Region</dt>
                  <dd className="font-mono text-[0.8125rem]">{claims.address.region}</dd>
                </>
              )}
            </dl>
          </div>
          <Button variant="ghost" size="sm" onClick={onLogout} disabled={busy}>
            Sign out
          </Button>
        </div>

        <div className="mt-4 border-t border-rule pt-3">
          <div className="doc-label mb-1">Registry serial — HMAC-SHA256 of the FIN, peppered</div>
          <CopyValue value={id.fin_hmac} accent />
          <p className="mt-2 text-[0.8125rem] leading-relaxed text-muted">
            The raw 12-digit FIN never leaves the server. A bare hash would be
            reversible in minutes, so the serial is an HMAC under a server-side
            pepper.
          </p>
        </div>

        {onAddPasskey && (
          <div className="mt-4 border-t border-rule pt-3">
            <div className="doc-label mb-1">Return without repeating verification</div>
            <div className="flex flex-wrap items-center gap-3">
              {viaPasskey ? (
                <Button variant="secondary" size="sm" disabled>
                  Register a passkey
                </Button>
              ) : (
                <Button variant="secondary" size="sm" onClick={onAddPasskey} disabled={busy}>
                  Register a passkey
                </Button>
              )}
              <span className="text-[0.8125rem] text-muted">
                {passkeys?.length
                  ? `${passkeys.length} registered on this identity`
                  : 'None registered yet'}
              </span>
            </div>
            <p className="mt-2 max-w-[58ch] text-[0.8125rem] leading-relaxed text-muted">
              {viaPasskey ? (
                <>
                  You are signed in with a passkey, so you can review and revoke
                  keys here but not add one. Verifying with Fayda again is what
                  adds a device — so anyone who reaches an open session cannot
                  quietly give themselves a permanent way back in.
                </>
              ) : (
                <>
                  Your device keeps the key and unlocks it with Face ID or a
                  fingerprint; the registry only stores the public half. It signs
                  you back in — it never re-proves your identity, which only
                  Fayda can do.
                </>
              )}
            </p>
            {/* A passkey outlives sign-out, so the list is the user's only way
                to notice one they did not add — and revoke is the only way to
                undo it. Both stay visible rather than tucked behind a menu. */}
            {passkeys?.length > 0 && (
              <ul className="mt-3 space-y-1.5">
                {passkeys.map((p) => (
                  <li
                    key={p.credential_id}
                    className="flex flex-wrap items-baseline justify-between gap-2 border-t border-rule pt-1.5"
                  >
                    <span className="text-[0.8125rem]">
                      {p.label || 'Unnamed device'}
                      <span className="ml-2 font-mono text-[0.75rem] text-muted">
                        added {String(p.created_at).slice(0, 10)}
                        {p.last_used_at
                          ? ` · last used ${String(p.last_used_at).slice(0, 10)}`
                          : ' · never used'}
                      </span>
                    </span>
                    {onRevokePasskey && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() => onRevokePasskey(p.credential_id)}
                      >
                        Revoke
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <details className="mt-3">
          <summary className="doc-label cursor-pointer">
            Claims returned by Fayda (held in a server-side session, never persisted)
          </summary>
          <pre className="mt-2 overflow-x-auto rounded-doc bg-surface px-4 py-3 font-mono text-[0.75rem] leading-relaxed">
            {JSON.stringify(claims, null, 2)}
          </pre>
        </details>
      </div>
    </Card>
  )
}
