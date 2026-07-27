import { useState } from 'react'
import { Card } from './ui/card.jsx'
import { Button } from './ui/button.jsx'
import { Alert } from './ui/alert.jsx'
import { api } from '../api.js'

/**
 * The compliance view (R4/F1): a verified identity's in-app timeline joined to
 * the on-chain history of the wallets they control.
 *
 * Two things are deliberate in how this presents. Every lookup demands a
 * written reason before the button works, because the reason is what a
 * reviewer reads later — making it a required field rather than an optional
 * note is the difference between an audit trail and a hit counter. And the
 * on-chain panel is fetched per wallet on request rather than with the case
 * file, so a slow explorer never delays the local record and its failure
 * states are shown as themselves rather than as an empty list.
 */
export function OperatorPanel() {
  const [reason, setReason] = useState('')
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [file, setFile] = useState(null)
  const [chainData, setChainData] = useState({})
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const ready = reason.trim().length >= 8

  async function run(fn) {
    setErr('')
    setBusy(true)
    try {
      await fn()
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const search = () =>
    run(async () => {
      setFile(null)
      setChainData({})
      const r = await api('/api/operator/search', { query, reason })
      setResults(r.results)
    })

  const open = (identity_id) =>
    run(async () => {
      setChainData({})
      setFile(await api('/api/operator/timeline', { identity_id, reason }))
    })

  const trace = (wallet) =>
    run(async () => {
      const key = `${wallet.chain}:${wallet.address}`
      setChainData((d) => ({ ...d, [key]: { loading: true } }))
      const r = await api('/api/operator/onchain', {
        identity_id: file.identity.id,
        chain: wallet.chain,
        address: wallet.address,
        reason,
      })
      setChainData((d) => ({ ...d, [key]: r }))
    })

  return (
    <section aria-labelledby="op-title" className="mt-8">
      <h2 className="doc-section" id="op-title">Compliance lookup</h2>

      <Alert tone="warning" title="Every lookup here is permanently logged.">
        Opening another person's record writes who you are, whose record, when,
        and the reason you give below to an append-only log. The person can read
        those entries. Binding a national identity to financial history has no
        settled lawful basis here yet — see the NBE/NIDP review.
      </Alert>

      <Card className="mt-4 p-5">
        <label className="doc-label block" htmlFor="op-reason">
          Reason for access (required, minimum 8 characters)
        </label>
        <input
          id="op-reason"
          className="mt-1 w-full rounded-doc border border-rule bg-surface px-3 py-2 font-ui text-[0.875rem]"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. AML review, case 4471"
        />

        <label className="doc-label mt-4 block" htmlFor="op-query">Name contains</label>
        <div className="mt-1 flex flex-wrap gap-2">
          <input
            id="op-query"
            className="min-w-[16rem] flex-1 rounded-doc border border-rule bg-surface px-3 py-2 font-mono text-[0.875rem]"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && ready && query) search() }}
          />
          <Button variant="primary" onClick={search} disabled={!ready || !query || busy}>
            Search
          </Button>
        </div>
        {!ready && (
          <p className="mt-2 text-[0.8125rem] text-muted">
            State a reason before searching — it is written to the log, not to a
            form that discards it.
          </p>
        )}
        {err && <div className="mt-4"><Alert tone="danger" title="Lookup refused.">{err}</Alert></div>}
      </Card>

      {results && (
        <Card className="mt-4 p-0 overflow-x-auto">
          <table className="ledger">
            <thead><tr><th>Identity</th><th>Verified</th><th /></tr></thead>
            <tbody>
              {results.length ? results.map((r) => (
                <tr key={r.id}>
                  <td data-label="Identity" className="font-ui">{r.display_name}</td>
                  <td data-label="Verified">{String(r.verified_at).slice(0, 10)}</td>
                  <td>
                    <Button variant="ghost" size="sm" onClick={() => open(r.id)} disabled={busy}>
                      Open case file
                    </Button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan={3} className="text-muted">No identity matched.</td></tr>
              )}
            </tbody>
          </table>
        </Card>
      )}

      {file && (
        <>
          <h3 className="doc-section mt-6">{file.identity.display_name}</h3>
          <Card className="p-5">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[0.875rem]">
              <dt className="doc-label pt-0.5">Born</dt>
              <dd className="font-mono">{file.identity.birthdate || '—'}</dd>
              <dt className="doc-label pt-0.5">Verified</dt>
              <dd className="font-mono">{String(file.identity.verified_at).slice(0, 19).replace('T', ' ')}</dd>
            </dl>
          </Card>

          <h3 className="doc-section mt-6">In-app history</h3>
          <Card className="p-0 overflow-x-auto">
            <table className="ledger">
              <thead><tr><th>When</th><th>Event</th><th>Wallet</th></tr></thead>
              <tbody>
                {file.timeline.map((e, i) => (
                  <tr key={`${e.at}-${i}`}>
                    <td data-label="When" className="whitespace-nowrap">
                      {String(e.at).slice(0, 19).replace('T', ' ')}
                    </td>
                    <td data-label="Event" className="font-ui">
                      {e.kind.replace(/_/g, ' ')}
                      <span className="block text-[0.75rem] text-muted">{e.detail}</span>
                    </td>
                    <td data-label="Wallet" className="max-w-[14rem] break-all font-mono text-[0.75rem]">
                      {e.address || <span className="text-muted">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <h3 className="doc-section mt-6">On-chain activity</h3>
          {file.wallets.length === 0 && (
            <Card className="p-5"><p className="text-muted">No active wallet to trace.</p></Card>
          )}
          {file.wallets.map((w) => {
            const key = `${w.chain}:${w.address}`
            const d = chainData[key]
            return (
              <Card key={key} className="mb-3 p-5">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="break-all font-mono text-[0.8125rem]">{w.address}</span>
                  <Button variant="secondary" size="sm" onClick={() => trace(w)} disabled={busy}>
                    {d ? 'Refresh' : 'Fetch on-chain history'}
                  </Button>
                </div>
                {d?.loading && <p className="mt-3 text-[0.8125rem] text-muted">Contacting the explorer…</p>}
                {d && !d.loading && d.status !== 'ok' && (
                  <div className="mt-3">
                    {/* The failure is shown AS a failure. An empty table here
                        would read as "this wallet has never transacted", which
                        is a different and much stronger claim. */}
                    <Alert tone="warning" title={
                      d.status === 'not_configured'
                        ? 'No blockchain explorer is configured — nothing was looked up.'
                        : 'The explorer could not be reached, so this is not a complete picture.'
                    }>
                      <span className="font-mono text-[0.75rem]">{d.status}{d.detail ? ` · ${d.detail}` : ''}</span>
                    </Alert>
                  </div>
                )}
                {d && !d.loading && d.status === 'ok' && (
                  <>
                    <table className="ledger mt-3">
                      <thead><tr><th>Hash</th><th>Direction</th><th>Counterparty</th><th>Value (wei)</th></tr></thead>
                      <tbody>
                        {d.transactions.length ? d.transactions.map((t) => (
                          <tr key={t.hash}>
                            <td data-label="Hash" className="max-w-[12rem] break-all font-mono text-[0.75rem]">{t.hash}</td>
                            <td data-label="Direction">{t.direction}</td>
                            <td data-label="Counterparty" className="max-w-[12rem] break-all font-mono text-[0.75rem]">{t.counterparty}</td>
                            <td data-label="Value (wei)" className="font-mono text-[0.75rem]">{t.value_wei}</td>
                          </tr>
                        )) : (
                          <tr><td colSpan={4} className="text-muted">No transactions returned for this address.</td></tr>
                        )}
                      </tbody>
                    </table>
                    <p className="mt-2 text-[0.8125rem] text-muted">
                      Public chain data, {d.cached ? 'from cache' : 'freshly fetched'}. Not stored by
                      this registry — it is refetched, never recorded.
                    </p>
                  </>
                )}
              </Card>
            )
          })}
        </>
      )}
    </section>
  )
}
