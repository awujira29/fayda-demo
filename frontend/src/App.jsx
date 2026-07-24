import { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import { signFor, useWalletConnection, PRIVY_CONFIGURED } from './wallet.js'
import {
  ChainCard, ConfirmButton, HistoryTable, IdentityCard,
  PrivySetupNotice, RegistryTable, SignPanel,
} from './components.jsx'

export default function App() {
  const conn = useWalletConnection()
  const [me, setMe] = useState(null)
  const [registry, setRegistry] = useState(null)
  const [pending, setPending] = useState(null) // {chain, address, nonce, message, wallet}
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    const [m, r] = await Promise.all([api('/api/me'), api('/api/registry')])
    setMe(m)
    setRegistry(r)
  }, [])

  useEffect(() => {
    load().catch((e) => setErr(e.message))
  }, [load])

  useEffect(() => {
    if (!ok) return
    const t = setTimeout(() => setOk(''), 6000)
    return () => clearTimeout(t)
  }, [ok])

  async function run(fn, doneMsg) {
    // Clear BOTH banners: a stale success surviving into a new action's
    // failure reads as two contradictory outcomes at once.
    setErr('')
    setOk('')
    setBusy(true)
    try {
      await fn()
      if (doneMsg) setOk(doneMsg)
      await load()
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const startBind = (chain, wallet) =>
    run(async () => {
      const n = await api('/api/wallet/nonce', { chain, address: wallet.address })
      setPending({ chain, address: wallet.address, nonce: n.nonce, message: n.message, wallet })
    })

  const sign = () =>
    run(async () => {
      // Test-key flow carries the server-produced signature; the wallet flow
      // signs here, in the browser, with the connected wallet.
      const sig = pending.testSignature
        ?? await signFor(pending.chain, pending.wallet, pending.message)
      const r = await api('/api/wallet/bind', {
        chain: pending.chain, address: pending.address,
        nonce: pending.nonce, signature: sig,
      })
      setPending(null)
      setOk(r.status === 'active'
        ? 'Wallet bound and active.'
        : `Replacement accepted. Activates in ${r.cooling_hours}h — the current wallet stays active until then.`)
    })

  const testKey = (chain) =>
    run(async () => {
      // Dev shortcut: the server generates a throwaway keypair, issues a nonce
      // and signs in one pass. Not how self-custody works — see the README.
      // The message is still shown for review before anything is submitted.
      const t = await api('/api/dev/test-wallet', { chain })
      setPending({
        chain, address: t.address, nonce: t.nonce, message: t.message,
        wallet: null, testSignature: t.signature,
      })
    })

  const cancelPending = (chain) =>
    run(() => api('/api/wallet/cancel', { chain, address: '' }), 'Pending change cancelled.')

  const fastForward = (chain) =>
    run(() => api('/api/dev/fast-forward', { chain, address: '' }), 'Cooling period collapsed.')

  const logout = () => run(async () => { await api('/logout', {}); setPending(null) })

  const resetAll = () =>
    run(async () => { await api('/api/dev/reset', {}); setPending(null) }, 'Registry wiped.')

  if (!me) {
    return (
      <div className="wrap">
        <div className="eyebrow">Internal proof of concept</div>
        <h1>Fayda identity → <strong>wallet registry</strong></h1>
        {err
          ? <div className="err">Backend unreachable: {err}. Start it with <span className="mono">APP_ENV=dev python backend/app.py</span>.</div>
          : <p className="sub">Loading…</p>}
      </div>
    )
  }

  return (
    <div className="wrap">
      <div className="eyebrow">Internal proof of concept</div>
      <h1>Fayda identity → <strong>wallet registry</strong></h1>
      <p className="sub">
        One Fayda-verified Ethiopian identity, bound to at most one verified
        self-custodied wallet per chain. No custody taken, no keys held.
      </p>

      <div className="banner">
        <strong>Mock Fayda.</strong> The identity provider here is local and not
        connected to the national register. The client code is real OIDC —
        authorization code flow, RS256 private-key-JWT client assertion — so
        production is an env var change. The claim shape matches the official
        client library (<span className="mono">github.com/National-ID-Program-Ethiopia/fayda-auth-python</span>).
      </div>

      {err && <div className="err">{err}</div>}
      {ok && <div className="ok">{ok}</div>}

      {!me.authenticated ? (
        <>
          <h2>Step 1 — verify identity</h2>
          <div className="card">
            <p className="flush">
              Authenticate with Fayda to establish a verified identity. In
              production this captures a fingerprint, iris, face or OTP.
            </p>
            <button onClick={() => { window.location.href = '/login' }}>Verify with Fayda</button>
          </div>
        </>
      ) : (
        <>
          <h2>Verified identity</h2>
          <IdentityCard me={me} onLogout={logout} />

          {!PRIVY_CONFIGURED && <PrivySetupNotice />}

          <h2>Bound wallets</h2>
          <div className="grid">
            {['evm', 'solana'].map((chain) => (
              <ChainCard
                key={chain}
                chain={chain}
                me={me}
                conn={conn}
                busy={busy}
                onConnect={conn.connect}
                onStartBind={startBind}
                onCancel={cancelPending}
                onFastForward={fastForward}
                onTestKey={testKey}
              />
            ))}
          </div>

          <SignPanel
            pending={pending}
            conn={conn}
            busy={busy}
            onSign={sign}
            onCancel={() => setPending(null)}
          />

          <h2>Binding history</h2>
          <HistoryTable history={me.history} />
        </>
      )}

      <h2>Registry</h2>
      <RegistryTable identities={registry ? registry.identities : []} />
      <div className="actions">
        <button className="ghost sm" onClick={() => load().catch((e) => setErr(e.message))}>
          Refresh
        </button>
        {me.dev && me.authenticated && (
          <ConfirmButton
            label="Reset everything"
            confirmLabel="Confirm: wipe all identities and bindings"
            onConfirm={resetAll}
            disabled={busy}
          />
        )}
      </div>
    </div>
  )
}
