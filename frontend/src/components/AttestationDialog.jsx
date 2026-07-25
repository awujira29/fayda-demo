import { Dialog, DialogContent, DialogTitle, DialogDescription } from './ui/dialog.jsx'
import { Button } from './ui/button.jsx'
import { Alert } from './ui/alert.jsx'

/**
 * The attestation: the one modal in the product, because signing needs
 * protected focus. The full server-issued message is always shown — no inner
 * scroll box, no clipped address; the dialog itself scrolls as one — and the
 * consent block states what the signature does, including that the binding
 * becomes a public record. phase: review | signature-pending | binding.
 */
export function AttestationDialog({ attest, conn, busy, onSign, onFreshTest, onClose }) {
  if (!attest) return null
  const { phase, message, address, network, wallet, error, testSignature } = attest

  // Live staleness check: if the account changed in the extension since the
  // message was issued, the address is no longer connected — block and say so.
  const stillConnected =
    !wallet || (conn.wallets || []).some((w) => w.address === address)

  const signing = phase === 'signature-pending'
  const binding = phase === 'binding'
  // A consumed or expired nonce cannot succeed on retry with the same stored
  // test signature — offer a fresh message instead of a dead-end loop.
  const deadTestRetry = Boolean(error && testSignature)

  return (
    <Dialog open onOpenChange={(open) => { if (!open && !binding) onClose() }}>
      <DialogContent aria-describedby="attest-desc">
        <p className="doc-label mb-2">Wallet attestation</p>
        <DialogTitle>Review, then sign</DialogTitle>
        <DialogDescription id="attest-desc" className="mt-1">
          {testSignature
            ? 'No wallet prompt will appear — in dev the server signs this exact message with a throwaway key. Read it before you bind.'
            : 'Your wallet will display this exact message. Read it before you sign.'}
        </DialogDescription>

        <pre className="mt-4 whitespace-pre-wrap break-words rounded-doc border border-rule bg-surface px-4 py-3 font-mono text-[0.75rem] leading-relaxed">
          {message}
        </pre>

        <ul className="mt-3 space-y-1 text-[0.8125rem] text-muted">
          <li>Signing only proves you control this wallet — it moves no funds and grants no spending permission.</li>
          <li>The binding becomes a public record: the registry lists your name and this address.</li>
          <li>The message is single-use and expires in five minutes.</li>
          {network && (
            <li>
              Wallet network: <span className="font-mono">{network}</span> — this
              signature is network-independent, so no switch is needed.
            </li>
          )}
        </ul>

        {!stillConnected && (
          <Alert tone="warning" className="mt-3" title="The wallet account changed.">
            <span className="font-mono text-[0.75rem]">{address}</span> is no
            longer the connected account in your extension. Close this and start
            again with the current account.
          </Alert>
        )}

        {error && (
          <Alert tone="danger" className="mt-3" title="The signature was not accepted.">
            {error}
            <span className="mt-1 block">
              {deadTestRetry
                ? 'The message below has been used or expired — request a fresh one and try again.'
                : 'Check that the account connected in your wallet matches the address in the message above, then sign again — or cancel and reconnect the right wallet.'}
            </span>
          </Alert>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-2">
          {deadTestRetry ? (
            <Button variant="primary" onClick={onFreshTest} disabled={busy}>
              Get a fresh message and retry
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={onSign}
              disabled={busy || !stillConnected || signing || binding}
            >
              {signing
                ? 'Waiting for your wallet…'
                : binding
                  ? 'Recording the binding…'
                  : testSignature
                    ? 'Bind with test-key signature'
                    : 'Sign in your wallet'}
            </Button>
          )}
          <Button variant="ghost" onClick={onClose} disabled={binding}>
            Cancel
          </Button>
          {signing && (
            <span role="status" className="doc-label !text-cooling-ink">
              Check your wallet extension — it is asking you to review and sign.
            </span>
          )}
        </div>

        {testSignature && (
          <p className="mt-3 text-[0.75rem] text-muted">
            Dev path: this throwaway key was generated and signed server-side.
            A real wallet never shares its key with the server.
          </p>
        )}

        <p className="mt-3 border-t border-rule pt-3 text-[0.75rem] leading-relaxed text-muted">
          The registry checks your signature against its own stored copy of this message.
        </p>
      </DialogContent>
    </Dialog>
  )
}
