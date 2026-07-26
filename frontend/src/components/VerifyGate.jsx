import { Card } from './ui/card.jsx'
import { Button } from './ui/button.jsx'
import { Alert } from './ui/alert.jsx'

/**
 * The verification handoff, presented the way Stripe Identity or Persona
 * present theirs: a formal step with clear expectations, not a login button.
 * In dev the biometric capture is simulated — that disclosure is load-bearing
 * and stays visible.
 */
export function VerifyGate({ simulated, onPasskey, busy, passkeyError }) {
  return (
    <section aria-labelledby="verify-title">
      <h2 className="doc-section" id="verify-title">Establish your identity</h2>
      <Card className="p-0 overflow-hidden">
        <div className="px-5 py-5">
          <p className="max-w-[58ch]">
            Binding a wallet starts with your national identity. You will be
            handed to <strong>Fayda eSignet</strong>, verify who you are, and
            return here with a verified record. The registry never sees your
            credentials — only signed claims.
          </p>
          <ol className="mt-4 space-y-2 text-[0.875rem]">
            {[
              ['1', 'Verify with Fayda', 'Biometric or OTP check against the national register.'],
              ['2', 'Connect your wallet', 'MetaMask or another wallet you already control.'],
              ['3', 'Sign one message', 'Proves control of the wallet. Moves no funds, grants no permissions.'],
            ].map(([n, title, sub]) => (
              <li key={n} className="flex gap-3">
                <span className="doc-label mt-0.5 inline-flex h-5 w-5 flex-none items-center justify-center rounded-full border border-rule-strong !text-ink">
                  {n}
                </span>
                <span>
                  <span className="font-semibold">{title}</span>
                  <span className="block text-[0.8125rem] text-muted">{sub}</span>
                </span>
              </li>
            ))}
          </ol>
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={() => { window.location.href = '/login' }}>
              Begin verification with Fayda
            </Button>
            {onPasskey && (
              <Button variant="ghost" onClick={onPasskey} disabled={busy}>
                {busy ? 'Waiting for your device…' : 'Returning? Use your passkey'}
              </Button>
            )}
          </div>
          {onPasskey && (
            <p className="mt-3 max-w-[58ch] text-[0.8125rem] text-muted">
              Once verified, you can register a passkey and return with Face ID
              or a fingerprint — no second trip through Fayda. Verification
              itself always comes from Fayda.
            </p>
          )}
          {passkeyError && (
            <div className="mt-4">
              <Alert tone="danger" title="That passkey did not sign you in.">
                {passkeyError}
              </Alert>
            </div>
          )}
        </div>
        {simulated && (
          <div className="border-t border-rule bg-surface px-5 py-3">
            <p className="text-[0.8125rem] text-muted">
              <span className="doc-label mr-2 !text-cooling-ink">Simulated environment</span>
              The next screen is a mock that <strong>simulates biometric
              capture</strong> — you pick a test resident instead of scanning a
              fingerprint. It is not connected to the national register.
            </p>
          </div>
        )}
      </Card>
    </section>
  )
}

/** Backend unreachable — a designed dead end with the recovery path. */
export function BackendDown({ detail }) {
  return (
    <Alert tone="danger" title="The registry backend is not reachable.">
      Start it with{' '}
      <code className="font-mono text-[0.8125rem]">
        PUBLIC_URL=http://localhost:5173 APP_ENV=dev python backend/app.py
      </code>{' '}
      and reload. <span className="text-muted">({detail})</span>
    </Alert>
  )
}

/** PUBLIC_URL mismatch — the half-login trap, surfaced instead of silent. */
export function OriginMismatch({ publicOrigin }) {
  return (
    <Alert tone="warning" title="Backend origin mismatch — sign-in would silently fail.">
      The backend expects the browser on{' '}
      <span className="font-mono text-[0.8125rem]">{publicOrigin}</span> but you
      are on <span className="font-mono text-[0.8125rem]">{window.location.origin}</span>.
      The session cookie would land on the wrong origin. Restart the backend
      with{' '}
      <code className="font-mono text-[0.8125rem]">
        PUBLIC_URL={window.location.origin} APP_ENV=dev python backend/app.py
      </code>
    </Alert>
  )
}
