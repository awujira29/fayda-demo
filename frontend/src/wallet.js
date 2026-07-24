/**
 * The wallet-provider seam — R2 in PROGRESS.md, made real.
 *
 * EVERY import from @privy-io lives in this file. The rest of the app sees
 * exactly four things: <WalletProvider>, useWalletConnection(), signFor(),
 * and PRIVY_CONFIGURED. Swapping Privy for another provider means rewriting
 * this file and nothing else.
 *
 * Privy is used for wallet CONNECTION only. Identity comes from Fayda. No
 * embedded wallets are created — external self-custody only, because the
 * registry's whole claim is "this verified person controls this key", and a
 * provider-held key would silently weaken that claim (R1 in PROGRESS.md).
 */
import { createElement } from 'react'
import { PrivyProvider, useConnectWallet, useWallets } from '@privy-io/react-auth'
import { useWallets as useSolanaWallets } from '@privy-io/react-auth/solana'

export const PRIVY_APP_ID = import.meta.env.VITE_PRIVY_APP_ID || ''
export const PRIVY_CONFIGURED = Boolean(PRIVY_APP_ID)

export function WalletProvider({ children }) {
  // Without an app id the provider is not mounted at all; the app renders a
  // setup notice instead of crashing inside Privy's context.
  if (!PRIVY_CONFIGURED) return children
  return createElement(
    PrivyProvider,
    {
      appId: PRIVY_APP_ID,
      config: {
        loginMethods: ['wallet'],
        embeddedWallets: {
          ethereum: { createOnLogin: 'off' },
          solana: { createOnLogin: 'off' },
        },
        appearance: {
          walletChainType: 'ethereum-and-solana',
          theme: 'light',
          accentColor: '#1F4E79',
        },
      },
    },
    children,
  )
}

function usePrivyConnection() {
  const { connectWallet } = useConnectWallet()
  const evm = useWallets()
  const solana = useSolanaWallets()
  return {
    configured: true,
    ready: evm.ready,
    // Both lists update reactively when the user switches accounts in the
    // wallet extension, so a stale address can never sit in the UI.
    wallets: { evm: evm.wallets, solana: solana.wallets },
    connect(chain) {
      connectWallet({
        walletChainType: chain === 'solana' ? 'solana-only' : 'ethereum-only',
      })
    },
  }
}

function useNullConnection() {
  return {
    configured: false,
    ready: true,
    wallets: { evm: [], solana: [] },
    connect() {},
  }
}

// Chosen once at module load: either Privy is configured for the whole session
// or it is not, so the hook identity is stable and the rules of hooks hold.
export const useWalletConnection = PRIVY_CONFIGURED
  ? usePrivyConnection
  : useNullConnection

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function b58encode(bytes) {
  const d = [0]
  for (const b of bytes) {
    let c = b
    for (let i = 0; i < d.length; i++) {
      c += d[i] << 8
      d[i] = c % 58
      c = (c / 58) | 0
    }
    while (c) {
      d.push(c % 58)
      c = (c / 58) | 0
    }
  }
  let s = ''
  for (const b of bytes) {
    if (b === 0) s += '1'
    else break
  }
  for (let i = d.length - 1; i >= 0; i--) s += B58[d[i]]
  return s
}

/**
 * Sign `message` with a connected wallet. Returns the signature in the exact
 * encoding backend/verify.py expects; the message itself is the server-issued
 * text and must be signed byte-for-byte.
 */
export async function signFor(chain, wallet, message) {
  if (chain === 'evm') {
    // personal_sign over the hex-encoded UTF-8 bytes. The wallet displays the
    // decoded text and signs the EIP-191 personal-message envelope — exactly
    // what eth_account's encode_defunct(text=...) + recover_message verify
    // server-side. Do not switch to eth_sign or typed data.
    const provider = await wallet.getEthereumProvider()
    const hex =
      '0x' +
      Array.from(new TextEncoder().encode(message))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
    return await provider.request({
      method: 'personal_sign',
      params: [hex, wallet.address],
    })
  }
  // Solana: plain ed25519 over the UTF-8 bytes, base58-encoded for PyNaCl.
  // NOTE: implemented against Privy v3.35's wallet-standard surface
  // (ConnectedStandardSolanaWallet.signMessage). Privy's docs contradict each
  // other on external Solana wallet support — see README before relying on it.
  const { signature } = await wallet.signMessage({
    message: new TextEncoder().encode(message),
  })
  return b58encode(signature)
}
