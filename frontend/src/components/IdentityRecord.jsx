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
export function IdentityRecord({ me, onLogout, busy }) {
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
