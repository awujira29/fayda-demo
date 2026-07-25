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

export function RegistryLedger({ identities }) {
  return (
    <Card className="p-0 overflow-x-auto">
      <table className="ledger">
        <thead>
          <tr><th>Identity</th><th>Ethereum</th><th>Solana</th></tr>
        </thead>
        <tbody>
          {identities.length ? (
            identities.map((i) => (
              <tr key={i.id}>
                <td data-label="Identity" className="font-ui">{i.display_name}</td>
                <td data-label="Ethereum" className="max-w-[14rem] break-all">
                  {i.evm || <span className="text-muted">—</span>}
                </td>
                <td data-label="Solana" className="max-w-[14rem] break-all">
                  {i.solana || <span className="text-muted">—</span>}
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={3} className="text-muted">The registry is empty.</td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  )
}
