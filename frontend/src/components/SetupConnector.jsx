import { Card } from './ui/card.jsx'
import { CopyValue } from './CopyValue.jsx'

/**
 * Missing connector configuration, designed as a setup step — an instruction
 * card in the registry's own voice, not an apologetic gray box.
 */
export function SetupConnector() {
  return (
    <Card className="p-0 overflow-hidden">
      <div className="border-b border-rule bg-surface px-5 py-3">
        <span className="doc-label">Wallet connector — setup required</span>
      </div>
      <div className="px-5 py-4">
        <p className="max-w-[58ch]">
          Wallet connections run through Privy. It needs a free app id
          (under 499 monthly users costs nothing) before real wallets can
          connect.
        </p>
        <ol className="mt-3 list-decimal space-y-1.5 pl-5 text-[0.875rem]">
          <li>
            Create an app at{' '}
            <span className="font-mono text-[0.8125rem]">dashboard.privy.io</span>
          </li>
          <li>
            Put the id in <span className="font-mono text-[0.8125rem]">frontend/.env.local</span>:
            <div className="mt-1.5 rounded-doc bg-surface px-3 py-2">
              <CopyValue value="VITE_PRIVY_APP_ID=<your app id>" />
            </div>
          </li>
          <li>Restart <span className="font-mono text-[0.8125rem]">npm run dev</span></li>
        </ol>
        <p className="mt-3 text-[0.8125rem] text-muted">
          Identity verification works without it. In the dev environment the
          throwaway test key below exercises the same signing path server-side.
        </p>
      </div>
    </Card>
  )
}
