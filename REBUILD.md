# Frontend rebuild spec

## Verified backend contract (confirm by reading, don't assume)
Endpoints, all same-origin through the Vite proxy:
  GET  /login /callback, POST /logout
  GET  /api/me -> { authenticated, identity, active, pending, dev, ... }
  GET  /api/registry
  POST /api/wallet/nonce {chain,address} -> {nonce,message,expires_in}
  POST /api/wallet/bind  {chain,address,nonce,signature} -> binding
  POST /api/wallet/cancel {chain}
  dev-only: /api/dev/fast-forward, /api/dev/reset, /api/dev/test-wallet

Bind handshake:
  1. POST /api/wallet/nonce -> server returns human-readable `message` + `nonce`
  2. wallet signs that EXACT message. EVM: personal_sign/EIP-191. Solana: ed25519
     over UTF-8 bytes, signature base58.
  3. POST /api/wallet/bind {chain,address,nonce,signature}
Server verifies the signature against the message IT stored; the nonce is bound to
(address,chain) so message and chain can't be swapped. Confirm via
store.consume_nonce. If code differs from this, trust the code and adapt.

## Wallet connection -- real, no simulation
Privy (@privy-io/react-auth) as connector only; identity comes from Fayda, not Privy.
loginMethods:['wallet'], embeddedWallets.createOnLogin:'off'. Real EIP-6963 discovery,
real MetaMask connect -> sign -> bind. Isolate every @privy-io import in src/wallet/;
nothing else imports it (swap seam). Solana: wire genuinely OR explicit disabled
"coming soon". Never fake a chain. Free tier: under 499 MAU.

## Fayda step -- not a toy
Dev mock stands in for biometric capture. Present like Stripe Identity / Persona, with
a dev-mode banner saying it simulates biometric capture. Surface residenceStatus
prominently (citizenship signal). Schema: sub, name, birthdate, gender, phone, picture,
residenceStatus, address{kebele,region,woreda,zone}.

## Design skills -- both layers required
VISUAL (how it looks): install Anthropic frontend-design plugin ->
  mkdir -p .claude/skills/frontend-design
  curl -o .claude/skills/frontend-design/SKILL.md https://raw.githubusercontent.com/anthropics/claude-code/main/plugins/frontend-design/skills/frontend-design/SKILL.md
  plus Impeccable: /plugin marketplace add pbakaus/impeccable
UX (whether it works): github.com/tommyjepsen/awesome-ux-skills (./install.sh);
use ux-heuristics-review + cognitive-load-conversion on bind/sign flows,
ai-trust-builders on every verify/sign screen.
Passing one layer and failing the other is not done.

## Look -- modern classic, not bonny
Restrained, financial-grade -- a bank or national registry, not a crypto app. NO
purple/violet gradients, glassmorphism, neon, mascot, marketing hero, pill-everything.
If it looks like a 2021 NFT mint page it's wrong. Real typeface (not Inter/Roboto/
system), weight contrast 300 vs 700, size steps 2-3x. Monospace for every address/
hash/identifier/figure. Tinted neutrals in OKLCH, never #000/#666; one accent for
identity/verification/active only. Dark + light, WCAG AA, usable at 380px. shadcn/ui
primitives themed to this, not default slate-and-blue. Every state designed: loading,
empty, error, disconnected, wrong-network, signature-pending, cooling, missing-config.
No raw error dumps.

## Keep what works
Vite proxy + BASE_URL/PUBLIC_URL split are correct and fail-safe. Preserve: proxy
/api /login /logout /callback /authorize /v1, one origin, PUBLIC_URL -> frontend origin.
Missing PUBLIC_URL -> clear notice, not silent half-login. If backend changes,
backend/t.py must still pass.

## How to work
Build -> verify against the goal -> fix what verification finds -> repeat. Not done
because code is written; done when checks pass. Use design-critic (screenshots+diffs
running UI) + Impeccable + ux-heuristics-review; fix only what they name,
current-value -> replacement, two passes. Auditor on anything changed. Extract tokens
to one file referenced from CLAUDE.md. Update CLAUDE.md: connector is Privy, frontend
is React+Vite.

## Done means
- old frontend gone; npm run dev renders the new one
- real MetaMask connects via Privy EIP-6963, signs server message, binds end to end
- reload preserves Fayda session AND wallet connection
- switching MetaMask account detected live, not stale
- Solana genuinely works OR honest disabled state, never faked
- backend/t.py passes
- both design layers applied (frontend-design+Impeccable visual, awesome-ux-skills
  heuristic), findings addressed
- DESIGN-REVIEW.md has screenshots desktop + 380px, no banned pattern
- auditor reports no new criticals/highs on changes, attention to Privy + origin split
- README documents both processes, Privy app-id, WalletConnect project-id (mobile), Solana truth
- claims relied on from CLAUDE.md/AUDIT.md but not independently confirmed are listed
  at the end as "assumed, unverified"
