import { Card } from './ui/card.jsx'
import { Badge } from './ui/badge.jsx'
import { CHAINS, fmt } from './ChainRecord.jsx'

export function HistoryLedger({ history }) {
  return (
    <Card className="p-0 overflow-x-auto">
      <table className="ledger">
        <thead>
          <tr>
            <th>Chain</th><th>Address</th><th>Status</th><th>Requested</th><th>Activates</th>
          </tr>
        </thead>
        <tbody>
          {history.length ? (
            history.map((b) => (
              <tr key={b.id}>
                <td data-label="Chain">{CHAINS[b.chain].label}</td>
                <td data-label="Address" className="max-w-[16rem] break-all">
                  {b.address}
                  {b.proof_method === 'dev-test-key' && (
                    <span className="doc-label ml-2 !text-cooling-ink">test key</span>
                  )}
                </td>
                {/* one vocabulary for one state: the card says Cooling, so
                    the ledger does too */}
                <td data-label="Status">
                  <Badge status={b.status === 'active' ? 'active' : b.status}>
                    {b.status === 'pending' ? 'cooling' : b.status}
                  </Badge>
                </td>
                <td data-label="Requested">{fmt(b.requested_at)}</td>
                <td data-label="Activates">{fmt(b.activates_at || b.activated_at)}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={5} className="text-muted">
                No entries yet — your first binding will appear here.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  )
}

/**
 * Who has looked at this person's record (R3). The registry ledger that used
 * to live here was the cross-user join — every verified person mapped to their
 * wallets — and moved behind the audited operator role. This replaces it with
 * the other direction: the surveillance capability, made visible to the person
 * subject to it.
 */
export function AccessLedger({ entries, total }) {
  return (
    <>
      <Card className="p-0 overflow-x-auto">
        <table className="ledger">
          <thead>
            <tr><th>When</th><th>Action</th><th>Stated reason</th></tr>
          </thead>
          <tbody>
            {entries.length ? (
              entries.map((e, i) => (
                <tr key={`${e.at}-${i}`}>
                  <td data-label="When" className="whitespace-nowrap">
                    {String(e.at).slice(0, 19).replace('T', ' ')}
                  </td>
                  <td data-label="Action" className="font-ui">
                    {e.action === 'view_identity'
                      ? 'Record opened'
                      : e.action === 'search_result'
                        ? 'Returned by a search'
                        : e.action}
                  </td>
                  <td data-label="Stated reason" className="max-w-[22rem]">{e.reason}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={3} className="text-muted">
                  No one has accessed your record.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
      {total > entries.length && (
        <p className="mt-2 text-[0.8125rem] text-muted">
          Showing {entries.length} of {total}. Entries are permanent — the log
          cannot be edited or deleted, including by the operators it records.
        </p>
      )}
    </>
  )
}
