/**
 * The wallet-connector seam. EVERY @privy-io import lives in this directory;
 * nothing outside src/wallet/ may import the connector. Swapping providers
 * means rewriting this module and nothing else.
 *
 * Privy is used for wallet CONNECTION only — identity comes from Fayda.
 * loginMethods is ['wallet'] and embedded wallet creation is off for both
 * chains: external self-custody wallets only, because the registry's claim is
 * "this verified person controls this key", and a provider-held key would
 * silently weaken that claim. Privy's connect modal performs EIP-6963
 * multi-wallet discovery, so multiple installed extensions are listed
 * side by side instead of fighting over window.ethereum.
 */
import { PrivyProvider, useConnectWallet, useWallets } from '@privy-io/react-auth'

// Build-time env wins for local dev; the backend-served runtime config
// (window.__PRIVY_APP_ID via /config.js) covers deploys, where the id is a
// plain env var and never requires a rebuild.
export const PRIVY_APP_ID =
  import.meta.env.VITE_PRIVY_APP_ID ||
  (typeof window !== 'undefined' && window.__PRIVY_APP_ID) ||
  ''
// A placeholder value from .env.example is not configuration.
export const PRIVY_CONFIGURED =
  PRIVY_APP_ID !== '' && !/your.?actual|your.?app|<.*>/i.test(PRIVY_APP_ID)

/**
 * Honesty constant: Privy's own documentation contradicts itself on whether
 * EXTERNAL Solana wallets are supported (the useSolanaWallets reference says
 * embedded-only; the connector guide shows external working). Until that is
 * verified against a live wallet, the Solana connect path stays off — a
 * disabled chain is honest, a silently failing button is not. The backend
 * already verifies ed25519, so enabling it later is frontend-only work.
 */
export const SOLANA_WALLETS_ENABLED = false

export function WalletProvider({ children }) {
  // Without an app id the provider is not mounted; the app renders a
  // designed setup state instead of crashing inside Privy's context.
  if (!PRIVY_CONFIGURED) return children
  return (
    <PrivyProvider
      appId={PRIVY_APP_ID}
      config={{
        loginMethods: ['wallet'],
        embeddedWallets: {
          ethereum: { createOnLogin: 'off' },
          solana: { createOnLogin: 'off' },
        },
        appearance: {
          walletChainType: 'ethereum-only',
          theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
        },
      }}
    >
      {children}
    </PrivyProvider>
  )
}

function usePrivyConnection() {
  const { connectWallet } = useConnectWallet()
  const { wallets, ready } = useWallets()
  return {
    configured: true,
    ready,
    // Live list: switching accounts in the extension updates it, so a stale
    // address can never sit in the UI unnoticed.
    wallets,
    connect: () => connectWallet({ walletChainType: 'ethereum-only' }),
  }
}

function useNullConnection() {
  return { configured: false, ready: true, wallets: [], connect: () => {} }
}

// Chosen once at module load; the hook identity is stable so the rules of
// hooks hold.
export const useWalletConnection = PRIVY_CONFIGURED ? usePrivyConnection : useNullConnection

/**
 * Sign `message` with a connected EVM wallet. personal_sign over the
 * hex-encoded UTF-8 bytes: the wallet shows the decoded text and signs the
 * EIP-191 personal-message envelope — exactly what the backend's
 * eth_account.encode_defunct(text=...) + recover_message verifies. Do not
 * switch to eth_sign or typed data.
 */
export async function signEvm(wallet, message) {
  const provider = await wallet.getEthereumProvider()
  const hex =
    '0x' +
    Array.from(new TextEncoder().encode(message))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  return await provider.request({ method: 'personal_sign', params: [hex, wallet.address] })
}

/** Current network of a connected wallet, for display only — the EIP-191
 * signature is chain-independent, so no network is "wrong", but showing it
 * avoids surprise when the wallet prompt appears on an unexpected chain. */
export async function currentNetwork(wallet) {
  try {
    const provider = await wallet.getEthereumProvider()
    const id = await provider.request({ method: 'eth_chainId' })
    const names = { '0x1': 'Ethereum Mainnet', '0xaa36a7': 'Sepolia', '0x89': 'Polygon', '0x2105': 'Base', '0xa4b1': 'Arbitrum One', '0xa': 'OP Mainnet' }
    return names[id] || `chain ${parseInt(id, 16)}`
  } catch {
    return null
  }
}
