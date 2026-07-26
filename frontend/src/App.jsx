/*
 * Direction contract —
 * THESIS: a national registry record, not a crypto app; the refusal is the
 *   NFT-mint page and the SaaS dashboard alike.
 * OWN-WORLD: issued-document language — OKLCH paper/ink neutrals, one Fayda
 *   green-teal accent spent only on identity/verification/active, Source
 *   Serif 4 300/700 display, Public Sans UI, Spline Sans Mono machine values,
 *   guilloché band, ruled ledgers, stamp-like status marks.
 * STORY: the visitor understands their identity is verified, sees exactly
 *   what a wallet binding proves, signs one legible message, and can read
 *   their record at a glance.
 * FIRST VIEWPORT: masthead (serif 300/700) over guilloché rule, then the
 *   verified-identity record or the verification handoff; primary action is
 *   the single accent button.
 * FORM: brief-pinned (financial-grade civil registry) — no tournament run;
 *   the brief beats the roll.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import { signEvm, currentNetwork, useWalletConnection, PRIVY_CONFIGURED } from './wallet/index.jsx'
import { RecordHeader } from './components/RecordHeader.jsx'
import { IdentityRecord } from './components/IdentityRecord.jsx'
import { VerifyGate, BackendDown, OriginMismatch } from './components/VerifyGate.jsx'
import { loginWithPasskey, registerPasskey, passkeysSupported } from './passkey.js'
import { SetupConnector } from './components/SetupConnector.jsx'
import { EvmRecord, SolanaRecord, CHAINS } from './components/ChainRecord.jsx'
import { AttestationDialog } from './components/AttestationDialog.jsx'
import { HistoryLedger, RegistryLedger } from './components/Ledgers.jsx'
import { Alert } from './components/ui/alert.jsx'
import { Button } from './components/ui/button.jsx'
import { Card } from './components/ui/card.jsx'

function Skeleton() {
  return (
    <div className="space-y-4">
      <p role="status" className="sr-only">Loading the registry…</p>
      <div aria-hidden="true" className="animate-pulse space-y-4">
        <div className="h-28 rounded-doc border border-rule bg-surface" />
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="h-40 rounded-doc border border-rule bg-surface" />
          <div className="h-40 rounded-doc border border-rule bg-surface" />
        </div>
      </div>
    </div>
  )
}

/** Two-step destructive control: one persistent button element so keyboard
 * focus survives arming; the second click confirms. */
function WipeButton({ onConfirm, disabled }) {
  const [armed, setArmed] = useState(false)
  return (
    <>
      <Button
        variant="danger"
        size="sm"
        disabled={disabled}
        onClick={() => {
          if (armed) { setArmed(false); onConfirm() } else setArmed(true)
        }}
      >
        {armed ? 'Confirm: erase every identity and binding' : 'Wipe registry (dev)'}
      </Button>
      {armed && (
        <Button variant="ghost" size="sm" onClick={() => setArmed(false)}>
          Keep everything
        </Button>
      )}
    </>
  )
}

export default function App() {
  const conn = useWalletConnection()
  const [me, setMe] = useState(null)
  const [registry, setRegistry] = useState(null)
  const [passkeyErr, setPasskeyErr] = useState('')
  const [attest, setAttest] = useState(null)
  const [fatal, setFatal] = useState('')
  const [err, setErr] = useState('')
  const [ok, setOk] = useState(null) // { msg, tone }
  const [busy, setBusy] = useState(false)
  // Bumped when the dialog closes; a signature resolving after abandonment
  // must not bind. The nonce is single-use and expires, so abandoning is safe.
  const attestGen = useRef(0)

  const load = useCallback(async () => {
    // Both at once. R2 made the registry authenticated, so a signed-out
    // visitor's request 401s — swallowed here, because this promise is what
    // the fatal-error boundary watches and a logged-out landing page must not
    // report a server failure. Awaiting /api/me first to decide whether to ask
    // would be tidier, but it serialises two round trips to a managed
    // database and the page visibly lags behind its own state.
    const [m, r] = await Promise.all([
      api('/api/me'),
      api('/api/registry').catch(() => null),
    ])
    // Set together: `me` alone renders the signed-in page against a null
    // registry, which the ledger states as "the registry is empty" — wrong
    // rather than merely pending.
    setMe(m)
    setRegistry(r)
    return m
  }, [])

  useEffect(() => {
    load().catch((e) => setFatal(e.message))
  }, [load])

  async function run(fn, done) {
    setErr('')
    setOk(null)
    setBusy(true)
    try {
      await fn()
      if (done) setOk(typeof done === 'string' ? { msg: done, tone: 'success' } : done)
      await load()
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  // Sign-in errors belong beside the sign-in button, not in the page-level
  // error slot the signed-in flows use — a signed-out visitor has no other
  // context to read them against. A cancelled biometric prompt is a normal
  // outcome (NotAllowedError), not a failure worth alarming anyone about.
  async function signInWithPasskey() {
    setPasskeyErr('')
    setBusy(true)
    try {
      await loginWithPasskey()
      await load()
    } catch (e) {
      if (e.name !== 'NotAllowedError' && e.name !== 'AbortError') {
        setPasskeyErr(e.message || 'Your device did not complete the check.')
      }
    } finally {
      setBusy(false)
    }
  }

  const addPasskey = () =>
    run(
      () => registerPasskey(navigator.platform || 'this device'),
      'Passkey registered. You can return with your device biometric.',
    )

  const revokePasskey = (credential_id) =>
    run(
      () => api('/api/passkey/revoke', { credential_id }),
      'Passkey revoked. That device can no longer sign in.',
    )

  const startBind = (chain, wallet) =>
    run(async () => {
      const [n, network] = await Promise.all([
        api('/api/wallet/nonce', { chain, address: wallet.address }),
        currentNetwork(wallet),
      ])
      setAttest({
        phase: 'review', chain, address: wallet.address, wallet, network,
        nonce: n.nonce, message: n.message, error: '',
      })
    })

  const testKey = (chain) =>
    run(async () => {
      const t = await api('/api/dev/test-wallet', { chain })
      setAttest({
        phase: 'review', chain, address: t.address, wallet: null, network: null,
        nonce: t.nonce, message: t.message, testSignature: t.signature, error: '',
      })
    })

  async function sign() {
    const gen = attestGen.current
    const a = attest
    setErr('')
    setBusy(true)
    try {
      let signature = a.testSignature
      if (!signature) {
        setAttest((s) => ({ ...s, phase: 'signature-pending', error: '' }))
        signature = await signEvm(a.wallet, a.message)
        // The user may have cancelled while the wallet prompt was open.
        if (attestGen.current !== gen) return
      }
      setAttest((s) => (s ? { ...s, phase: 'binding' } : s))
      const r = await api('/api/wallet/bind', {
        chain: a.chain, address: a.address, nonce: a.nonce, signature,
      })
      if (attestGen.current !== gen) return
      setAttest(null)
      const label = CHAINS[a.chain].label
      setOk(
        r.status === 'active'
          ? { msg: `Wallet bound. It is now your verified ${label} wallet.`, tone: 'success' }
          : { msg: `Replacement recorded for ${label}. It activates in ${r.cooling_hours} hours — your current wallet stays active until then.`, tone: 'warning' },
      )
      await load()
    } catch (e) {
      if (attestGen.current === gen) {
        setAttest((s) => (s ? { ...s, phase: 'review', error: e.message } : s))
      }
    } finally {
      setBusy(false)
    }
  }

  const closeAttest = () => {
    attestGen.current += 1
    setAttest(null)
  }

  const cancelPending = (chain) =>
    run(() => api('/api/wallet/cancel', { chain, address: '' }),
      `Replacement cancelled. Your current ${CHAINS[chain].label} wallet stays active.`)
  const fastForward = (chain) =>
    run(() => api('/api/dev/fast-forward', { chain, address: '' }),
      `Cooling skipped (dev). The ${CHAINS[chain].label} replacement is now active.`)
  const logout = () => run(async () => { await api('/logout', {}); closeAttest() })
  const wipe = () => run(async () => { await api('/api/dev/reset', {}); closeAttest() }, 'Registry wiped.')

  const originMismatch =
    me && !me.authenticated && me.public_origin &&
    !me.public_origin.startsWith(window.location.origin)

  return (
    <div className="mx-auto max-w-[60rem] px-6 pb-24 pt-10 max-[420px]:px-4 max-[420px]:pt-6">
      <RecordHeader />

      {fatal ? (
        <BackendDown detail={fatal} />
      ) : !me ? (
        <Skeleton />
      ) : (
        <>
          {err && <Alert tone="danger" className="mb-4">{err}</Alert>}
          <div role="status" aria-live="polite">
            {ok && (
              <Alert tone={ok.tone} role="presentation" className="mb-4">
                {ok.msg}
              </Alert>
            )}
          </div>
          {originMismatch && <div className="mb-4"><OriginMismatch publicOrigin={me.public_origin} /></div>}

          {!me.authenticated ? (
            <VerifyGate
              simulated={me.dev || me.demo}
              onPasskey={passkeysSupported() ? signInWithPasskey : null}
              busy={busy}
              passkeyError={passkeyErr}
            />
          ) : (
            <>
              <h2 className="doc-section">Identity</h2>
              <IdentityRecord
                me={me} onLogout={logout} busy={busy}
                onAddPasskey={passkeysSupported() ? addPasskey : null}
                onRevokePasskey={revokePasskey}
                passkeys={me.passkeys}
              />

              {!PRIVY_CONFIGURED && (
                <>
                  <h2 className="doc-section">Wallet connector</h2>
                  <SetupConnector />
                </>
              )}

              <h2 className="doc-section">Bound wallets</h2>
              <div className="grid gap-4 sm:grid-cols-2">
                <EvmRecord
                  me={me} conn={conn} busy={busy}
                  onStartBind={startBind} onCancel={cancelPending}
                  onFastForward={fastForward} onTestKey={testKey}
                />
                <SolanaRecord
                  me={me} busy={busy}
                  onCancel={cancelPending} onFastForward={fastForward} onTestKey={testKey}
                />
              </div>

              <h2 className="doc-section">Binding history</h2>
              <HistoryLedger history={me.history} />
            </>
          )}

          {me.authenticated && (
            <>
              <h2 className="doc-section">Registry</h2>
              <RegistryLedger identities={registry ? registry.identities : []} />
              <div className="mt-3 flex flex-wrap gap-2">
                <Button variant="ghost" size="sm" onClick={() => load().catch((e) => setErr(e.message))}>
                  Refresh
                </Button>
                {me.dev && <WipeButton onConfirm={wipe} disabled={busy} />}
              </div>
            </>
          )}

          {me.authenticated && !me.dev && (
            <Card className="mt-8 border-rule bg-surface">
              <p className="text-[0.8125rem] text-muted">
                This is an internal proof of concept, not an official government
                service. Bindings recorded here carry no legal weight.
              </p>
            </Card>
          )}
        </>
      )}

      <AttestationDialog
        attest={attest} conn={conn} busy={busy}
        onSign={sign}
        onFreshTest={() => testKey(attest.chain)}
        onClose={closeAttest}
      />
    </div>
  )
}
