import { useState } from 'react'
import { Card } from './ui/card.jsx'
import { Button } from './ui/button.jsx'
import { Badge } from './ui/badge.jsx'
import { CopyValue } from './CopyValue.jsx'
import { SOLANA_WALLETS_ENABLED } from '../wallet/index.jsx'

export const CHAINS = {
  evm: { label: 'Ethereum', short: 'ETH' },
  solana: { label: 'Solana', short: 'SOL' },
}

export function fmt(t) {
  return t
    ? new Date(t).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
      })
    : '—'
}

function hoursUntil(t) {
  const h = Math.round((new Date(t) - Date.now()) / 3_600_000)
  return h > 0 ? h : null
}

/** Two-step arm for the dev cooling skip — one persistent element, same
 * pattern as the registry wipe: irreversible dev actions match. */
function ArmButton({ label, confirmLabel, onConfirm, disabled }) {
  const [armed, setArmed] = useState(false)
  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        disabled={disabled}
        onClick={() => {
          if (armed) { setArmed(false); onConfirm() } else setArmed(true)
        }}
      >
        {armed ? confirmLabel : label}
      </Button>
      {armed && (
        <Button variant="ghost" size="sm" onClick={() => setArmed(false)}>
          Keep cooling
        </Button>
      )}
    </>
  )
}

function ActiveBlock({ active }) {
  return (
    <div className="mt-3">
      <div className="doc-label mb-1">Verified wallet</div>
      <CopyValue value={active.address} accent />
      <div className="doc-label mt-1.5">Active since {fmt(active.activated_at)}</div>
    </div>
  )
}

function CoolingBlock({ chain, pending, dev, busy, onCancel, onFastForward }) {
  const hrs = hoursUntil(pending.activates_at)
  return (
    <div className="mt-4 border-t border-rule pt-3">
      <div className="flex items-center justify-between gap-3">
        <span className="doc-label">Replacement under cooling</span>
        <Badge status="pending">Cooling</Badge>
      </div>
      <CopyValue value={pending.address} className="mt-1.5" />
      <div className="doc-label mt-1.5">
        Activates {fmt(pending.activates_at)}{hrs ? ` — in about ${hrs} hours` : ''}
      </div>
      <p className="mt-2 text-[0.8125rem] leading-relaxed text-muted">
        Your current wallet stays active until then — no gap in service. If you
        did not request this change, cancel it now: the delay exists precisely
        so a hijacked session cannot swap your wallet instantly.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button variant="danger" size="sm" onClick={() => onCancel(chain)} disabled={busy}>
          Cancel replacement
        </Button>
        {dev && (
          <ArmButton
            label="Skip cooling (dev)"
            confirmLabel="Confirm: activate replacement now (dev)"
            onConfirm={() => onFastForward(chain)}
            disabled={busy}
          />
        )}
      </div>
    </div>
  )
}

/** Ethereum: the real path — connect through the Privy modal, then attest. */
export function EvmRecord({ me, conn, busy, onStartBind, onCancel, onFastForward, onTestKey }) {
  const active = me.active.evm
  const pending = me.pending.evm
  const wallets = conn.wallets
  const [pick, setPick] = useState(0)
  const wallet = wallets[Math.min(pick, Math.max(wallets.length - 1, 0))] || null

  return (
    <Card>
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-semibold">{CHAINS.evm.label}</h3>
        {active ? <Badge status="active">Active</Badge> : <Badge status="none">Not bound</Badge>}
      </div>

      {active
        ? <ActiveBlock active={active} />
        : <p className="mt-2 text-[0.8125rem] text-muted">No wallet is bound on this chain yet.</p>}

      {pending ? (
        <CoolingBlock
          chain="evm" pending={pending} dev={me.dev} busy={busy}
          onCancel={onCancel} onFastForward={onFastForward}
        />
      ) : (
        <div className="mt-4 border-t border-rule pt-3">
          {wallet && (
            <div className="mb-3">
              <div className="doc-label mb-1">Connected wallet{wallets.length > 1 ? 's' : ''}</div>
              {wallets.length > 1 ? (
                <select
                  aria-label="Choose which connected wallet to bind"
                  className="doc-value w-full rounded-doc border border-rule-strong bg-card px-2 py-1.5"
                  value={pick}
                  onChange={(e) => setPick(Number(e.target.value))}
                >
                  {wallets.map((w, i) => (
                    <option key={w.address} value={i}>
                      {w.address} {w.walletClientType ? `(${w.walletClientType})` : ''}
                    </option>
                  ))}
                </select>
              ) : (
                <CopyValue value={wallet.address} />
              )}
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            {wallet && (
              <Button variant="primary" size="sm" onClick={() => onStartBind('evm', wallet)} disabled={busy}>
                {active ? 'Replace with this wallet' : 'Bind this wallet'}
              </Button>
            )}
            {conn.configured && (
              <Button variant="outline" size="sm" onClick={conn.connect} disabled={busy}>
                {wallets.length ? 'Connect another wallet' : 'Connect wallet'}
              </Button>
            )}
            {me.dev && (
              <Button variant="outline" size="sm" onClick={() => onTestKey('evm')} disabled={busy}>
                Bind a throwaway test key (dev)
              </Button>
            )}
          </div>
        </div>
      )}
    </Card>
  )
}

/**
 * Solana: honestly disabled. External Solana wallet support in the connector
 * is unverified (its docs contradict each other), and a button that silently
 * fails is worse than a chain that says it is not ready. The backend already
 * verifies ed25519 — enabling this is frontend-only work once verified.
 */
export function SolanaRecord({ me, busy, onCancel, onFastForward, onTestKey }) {
  const active = me.active.solana
  const pending = me.pending.solana
  return (
    <Card>
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-semibold">{CHAINS.solana.label}</h3>
        {active ? <Badge status="active">Active</Badge> : <Badge status="none">Not bound</Badge>}
      </div>

      {active
        ? <ActiveBlock active={active} />
        : <p className="mt-2 text-[0.8125rem] text-muted">No wallet is bound on this chain yet.</p>}

      {pending ? (
        <CoolingBlock
          chain="solana" pending={pending} dev={me.dev} busy={busy}
          onCancel={onCancel} onFastForward={onFastForward}
        />
      ) : (
        <div className="mt-4 border-t border-rule pt-3">
          {!SOLANA_WALLETS_ENABLED && (
            <div>
              <div className="doc-label mb-1">Wallet connection — not yet enabled</div>
              <p className="text-[0.8125rem] leading-relaxed text-muted">
                External Solana wallet support in our connector is unverified,
                so this path is off rather than unreliable. The registry
                already verifies Solana signatures server-side; connection will
                be enabled once the connector is proven against a real wallet.
              </p>
            </div>
          )}
          {me.dev && (
            <div className="mt-3">
              <Button variant="outline" size="sm" onClick={() => onTestKey('solana')} disabled={busy}>
                Bind a throwaway test key (dev)
              </Button>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
