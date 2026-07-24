import { useEffect, useState } from 'react'
import { PRIVY_CONFIGURED } from './wallet.js'

export const CHAINS = {
  evm: { label: 'Ethereum', wallet: 'MetaMask or Rabby' },
  solana: { label: 'Solana', wallet: 'Phantom or Solflare' },
}

export function fmt(t) {
  return t
    ? new Date(t).toLocaleString(undefined, {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
      })
    : '—'
}

/**
 * Address/hash as a real button: reachable and copyable from the keyboard,
 * shares the global focus ring, and still mouse/touch-selectable.
 */
export function CopyValue({ value }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 1800)
    return () => clearTimeout(t)
  }, [copied])
  return (
    <button
      type="button"
      className="addr"
      title="Copy to clipboard"
      onClick={() => navigator.clipboard?.writeText(value).then(() => setCopied(true))}
    >
      {value}
      {copied && <span className="copied" aria-live="polite">copied</span>}
    </button>
  )
}

export function IdentityCard({ me, onLogout }) {
  const id = me.identity
  return (
    <div className="card">
      <div className="row">
        <div>
          <div className="id-name">{id.display_name}</div>
          <div className="label id-meta">Born <span className="mono">{id.birthdate || '—'}</span></div>
          {/* residenceStatus value set is unconfirmed (NIDP) — display verbatim,
              never branch on it */}
          <div className="label">Residence status <span className="mono">{me.claims?.residenceStatus || '—'}</span></div>
        </div>
        <button className="ghost sm" onClick={onLogout}>Sign out</button>
      </div>
      <div className="stack">
        <div className="label">Stored identifier — HMAC-SHA256, peppered</div>
        <CopyValue value={id.fin_hmac} />
      </div>
      <p className="note">
        The raw 12-digit FIN is never written to the database. A bare hash would
        be pointless here — 10<sup>12</sup> values is enumerable in minutes — so
        this is an HMAC under a server-side pepper.
      </p>
      <details className="stack-sm">
        <summary className="claims-summary">Claims returned by userinfo (server-side session, not persisted)</summary>
        <div className="msgbox">{JSON.stringify(me.claims, null, 2)}</div>
      </details>
    </div>
  )
}

export function PrivySetupNotice() {
  return (
    <div className="card">
      <div className="label">Wallet connection not configured</div>
      <p className="stack-sm flush-b">
        Wallet connection runs through Privy and needs an app id. Create one at{' '}
        <span className="mono">dashboard.privy.io</span>, then:
      </p>
      <div className="msgbox">{'echo "VITE_PRIVY_APP_ID=<your app id>" > frontend/.env.local\nnpm run dev'}</div>
      <p className="note">
        Identity verification and the throwaway-test-key path work without it —
        only real wallet connections need the app id.
      </p>
    </div>
  )
}

export function ChainCard({ chain, me, conn, busy, onConnect, onStartBind, onCancel, onFastForward, onTestKey }) {
  const L = CHAINS[chain]
  const active = me.active[chain]
  const pending = me.pending[chain]
  const wallets = conn.wallets[chain] || []
  const [pick, setPick] = useState(0)
  const wallet = wallets[Math.min(pick, wallets.length - 1)] || null

  return (
    <div className="card">
      <div className="row">
        <div className="chain-name">{L.label}</div>
        {active
          ? <span className="pill p-active">Active</span>
          : <span className="pill p-empty">Not bound</span>}
      </div>

      {active ? (
        <div className="stack">
          <div className="label">Verified wallet</div>
          <CopyValue value={active.address} />
          <div className="label stack-sm">Since {fmt(active.activated_at)}</div>
        </div>
      ) : (
        <p className="note stack-sm">No wallet bound on this chain yet.</p>
      )}

      {pending ? (
        <div className="divider">
          <div className="row">
            <div className="label flush">Replacement pending</div>
            <span className="pill p-pending">Cooling</span>
          </div>
          <CopyValue value={pending.address} />
          <div className="label stack-sm">Activates {fmt(pending.activates_at)}</div>
          <div className="actions">
            <button className="danger sm" onClick={() => onCancel(chain)} disabled={busy}>Cancel change</button>
            {me.dev && (
              <button className="ghost sm" onClick={() => onFastForward(chain)} disabled={busy}>
                Fast-forward (dev)
              </button>
            )}
          </div>
          <p className="note">
            The incumbent stays active throughout, so there is no gap in service.
            If someone else initiated this, cancelling here stops it.
          </p>
        </div>
      ) : (
        <div className="stack">
          {wallets.length > 0 && (
            <div className="stack-sm">
              <div className="label">Connected wallet</div>
              {wallets.length > 1 ? (
                <select
                  className="wallet-select"
                  value={pick}
                  onChange={(e) => setPick(Number(e.target.value))}
                >
                  {wallets.map((w, i) => (
                    <option key={w.address} value={i}>{w.address}</option>
                  ))}
                </select>
              ) : (
                <CopyValue value={wallet.address} />
              )}
            </div>
          )}
          <div className="actions">
            {wallet && (
              <button className="sm" onClick={() => onStartBind(chain, wallet)} disabled={busy}>
                {active ? 'Replace with this wallet' : 'Prove control & bind'}
              </button>
            )}
            {PRIVY_CONFIGURED && (
              <button className="ghost sm" onClick={() => onConnect(chain)} disabled={busy}>
                {wallets.length ? 'Connect another wallet' : `Connect ${L.wallet}`}
              </button>
            )}
            {me.dev && (
              <button className="ghost sm" onClick={() => onTestKey(chain)} disabled={busy}>
                Throwaway test key (dev)
              </button>
            )}
          </div>
          {!PRIVY_CONFIGURED && (
            <p className="note">Wallet connection needs a Privy app id — see the setup card above.</p>
          )}
        </div>
      )}
    </div>
  )
}

export function SignPanel({ pending, conn, busy, onSign, onCancel }) {
  if (!pending) return null
  // The wallet list is live: if the user switched accounts in the extension
  // after the nonce was issued, the address we would sign for is no longer
  // connected. Surface that instead of letting the signature fail obscurely.
  const stillConnected =
    !pending.wallet ||
    (conn.wallets[pending.chain] || []).some((w) => w.address === pending.address)
  return (
    <>
      <h2>Sign to prove control</h2>
      <div className="card">
        <div className="label">Message issued by the server</div>
        <div className="msgbox">{pending.message}</div>
        {!stillConnected && (
          <div className="err">
            The wallet for <span className="mono">{pending.address}</span> is no
            longer connected — the account changed in your wallet extension.
            Cancel and start again with the current account.
          </div>
        )}
        <div className="actions">
          <button onClick={onSign} disabled={busy || !stillConnected}>
            {pending.testSignature ? 'Bind with test-key signature' : 'Sign with wallet'}
          </button>
          <button className="ghost" onClick={onCancel} disabled={busy}>Cancel</button>
        </div>
        <p className="note">
          The signature proves control of the private key. It authorises nothing
          and cannot move funds. The server verifies against its own stored copy
          of this message, never the one the browser sends back.
          {pending.testSignature && ' This throwaway key was generated and signed server-side — a dev-only stand-in for a real wallet.'}
        </p>
      </div>
    </>
  )
}

export function HistoryTable({ history }) {
  return (
    <div className="card table-card">
      <table className="stacking-table">
        <thead>
          <tr><th>Chain</th><th>Address</th><th>Status</th><th>Requested</th><th>Activates</th></tr>
        </thead>
        <tbody>
          {history.length ? history.map((b) => (
            <tr key={b.id}>
              <td data-label="Chain">{CHAINS[b.chain].label}</td>
              <td data-label="Address" className="cell-addr">{b.address}</td>
              <td data-label="Status"><span className={`pill p-${b.status}`}>{b.status}</span></td>
              <td data-label="Requested">{fmt(b.requested_at)}</td>
              <td data-label="Activates">{fmt(b.activates_at || b.activated_at)}</td>
            </tr>
          )) : (
            <tr><td className="empty" colSpan={5}>No bindings yet</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export function RegistryTable({ identities }) {
  return (
    <div className="card table-card">
      <table>
        <thead>
          <tr><th>Identity</th><th>Ethereum</th><th>Solana</th></tr>
        </thead>
        <tbody>
          {identities.length ? identities.map((i) => (
            <tr key={i.id}>
              <td>{i.display_name}</td>
              <td className="cell-addr-sm">{i.evm || <span className="empty">—</span>}</td>
              <td className="cell-addr-sm">{i.solana || <span className="empty">—</span>}</td>
            </tr>
          )) : (
            <tr><td className="empty" colSpan={3}>Registry empty</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

/** Two-step destructive button: first click arms, second confirms. */
export function ConfirmButton({ label, confirmLabel, onConfirm, disabled }) {
  const [armed, setArmed] = useState(false)
  if (!armed) {
    return (
      <button className="danger sm" onClick={() => setArmed(true)} disabled={disabled}>
        {label}
      </button>
    )
  }
  return (
    <>
      <button className="danger sm" onClick={() => { setArmed(false); onConfirm() }} disabled={disabled}>
        {confirmLabel}
      </button>
      <button className="ghost sm" onClick={() => setArmed(false)}>Keep everything</button>
    </>
  )
}
