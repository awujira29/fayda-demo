# Design review — Fayda wallet registry frontend

Method: rendered every state (desktop + 380px, light + dark) into `screenshots/`
and diffed against `DESIGN.md` / `PRODUCT.md` and the token source
`frontend/src/styles/tokens.css`. Contrast is computed from the OKLCH tokens
that produce the pixels (not eyedropped from compressed PNGs) — see
`scratchpad/contrast.py` / `hex.py`. Report only; no files changed except this
one. Privy connect-modal states are not capturable (no app id) — noted as a gap,
not reviewed blind.

This file reviews the **rebuilt** React + Vite + Tailwind 4 frontend (Source
Serif 4 / Public Sans / Spline Sans Mono, one green-teal accent). The prior
contents reviewed the deleted vanilla-JS frontend and have been replaced.

---

## 2026-07-24 — pass one

Seven states at two widths and two themes. The build is authored, not defaulted:
serif 300/700 masthead split, mono for every machine value, a strict semantic
accent, a guilloché band, ruled ledgers that stack at 380px. Findings below are
one real breakage plus colour-discipline drift — not a rebuild. Grouped by
severity.

### HIGH

**1. The attestation signing message is scroll-trapped and clips at 380px.**
Screenshots: `04-attestation-380px.png`, `07-error-380px.png` — both end the
message box at `URI: http://127.0.0.1:8000`; **Chain**, **Nonce** and **Issued
At** are cut off below the fold. On desktop (`04-attestation.png`) the full
message fits, so the bug only bites the mobile-first user the product is built
for.
- Offending line: `frontend/src/components/AttestationDialog.jsx:32`
- Current: `<pre className="mt-4 max-h-[36vh] overflow-y-auto whitespace-pre-wrap rounded-doc border border-rule bg-surface px-4 py-3 font-mono text-[0.75rem] leading-relaxed">`
- Replacement: drop `max-h-[36vh] overflow-y-auto` →
  `<pre className="mt-4 whitespace-pre-wrap rounded-doc border border-rule bg-surface px-4 py-3 font-mono text-[0.75rem] leading-relaxed">`.
  The dialog container already scrolls as one unit
  (`dialog.jsx:18`, `max-h-[88vh] overflow-y-auto`), so the whole message renders
  and the user scrolls the dialog — never a hidden inner box.
- Why HIGH: this is the one screen where the user authorises something with a
  key. The clipped lines are the anti-replay **Nonce** and the **Issued At** that
  back the "single-use and expires in five minutes" promise printed directly
  below the box. The consent copy claims properties the user cannot see on a
  phone. `DESIGN.md` / the review brief both state the message must be "never
  truncated, never scroll-trapped."

### MEDIUM

**2. A pending replacement is confirmed in the active/verification accent.**
Screenshot: `06-cooling.png` (top banner, green) vs the `COOLING` pill (amber) on
the same screen. The success banner "Replacement recorded. It activates in 72
hours — your current wallet stays active until then." reports a **pending**
outcome but renders in green — the accent `DESIGN.md` reserves for
identity/verification/**active**. Banner colour contradicts the badge colour for
the same state.
- Offending lines: `frontend/src/App.jsx:178` (`{ok && <Alert tone="success">}`
  for every success) and the message set at `App.jsx:144`.
- Current: one `ok` string → always `tone="success"` (verify green).
- Replacement: carry a tone with the message (e.g. `setOk({ msg, tone })`), keep
  "Wallet bound … active" (`App.jsx:143`) as `tone="success"`, and give
  "Replacement recorded … activates in Nh" (`App.jsx:144`) `tone="warning"`
  (cooling amber). Aligns the banner with the pending semantic and keeps green
  exclusive to active — the accent's whole discipline.

### LOW

**3. The `--faint` em-dash placeholder is below AA in light theme.**
Screenshot: `03-identity-record.png` (PUBLIC REGISTRY, Solana `—`). `--faint
oklch(0.62 0.012 250)` on paper measures **3.38:1** (dark 4.19:1) — under the
4.5:1 text minimum. Only the "no wallet bound" dash uses it (`Ledgers.jsx:51,54`),
so impact is small, but it is rendered text.
- Current: `--faint: oklch(0.62 0.012 250)` (tokens.css:17).
- Replacement: darken to ~`oklch(0.55 0.014 250)` (≈4.6:1 on paper), or render the
  dash at `--muted`; reserve `--faint` for non-text rules only.

**4. The guilloché masthead band is drawn in the reserved accent.**
Screenshot: every state, the teal band under the masthead. `RecordHeader.jsx:47`
wraps `<Guilloche/>` in `text-verify`. `DESIGN.md` spends the accent "exclusively
[on] identity, verification and active state … if it appears on anything else, it
is a bug," and the band is a decorative security-print texture, not a state.
- Current: `<div className="mt-5 text-verify"><Guilloche/></div>`.
- Replacement (if strict): `text-rule-strong` or `text-ink/30`. Keep `text-verify`
  only if the band is explicitly accepted as an authenticity/verification mark —
  in which case record that exception in `DESIGN.md` so it is not re-flagged.
  Borderline; author's call.

**5. The Privy connect modal theme is hardcoded light.**
Not capturable (no app id) — flagged from code. `wallet/index.jsx:44` sets
`appearance: { walletChainType: 'ethereum-only', theme: 'light' }`. In dark mode
the wallet-connect modal would render light — a visible seam mid-flow.
- Current: `theme: 'light'`.
- Replacement: derive from `document.documentElement.dataset.theme` at mount/connect
  so the modal follows the app theme.

Cosmetic, not numbered: at 380px "Sign out" wraps to an orphaned line between the
identity `<dl>` and the REGISTRY SERIAL rule (`05-one-bound-380px.png`,
`06-cooling-380px.png`) — legible and reachable, just loosely placed. The
Ethereum "NOT BOUND" card carries a tall void because the grid matches the taller
Solana card (`03-identity-record.png`) — normal equal-height grid behaviour.

---

## 2026-07-24 — pass two (verification close-out)

Fresh screenshots at both widths and themes re-shot after the fixes. Each applied
change was checked in the render, or in code where the change is not visual (Privy
modal, ARIA, provenance flags). This is the second and final pass of the two-pass
process — no new subjective threads opened; only landed / not-landed and
regressions. **Every applied item landed. No regression found. No open finding
remains.**

### Pass-one findings — all closed

- **Finding 1 (HIGH) — signing message clipped at 380px → RESOLVED.**
  `AttestationDialog.jsx:38` now reads `mt-4 whitespace-pre-wrap break-words …` —
  `max-h-[36vh] overflow-y-auto` gone. `04-attestation-380px.png` renders the whole
  message: the full EVM address on its own wrapped line, then **Chain**, **Nonce**,
  **Issued At** and the new **Expiration Time** all above the fold; the dialog
  scrolls as one unit, no inner box. Verified again on `06-cooling-380px.png` and
  `07-error.png`.
- **Finding 2 (MEDIUM) — pending outcome shown in the active accent → RESOLVED.**
  `setOk` now carries a tone (`App.jsx:79,102`). `06-cooling.png`: "Replacement
  recorded for Ethereum. It activates in 72 hours …" renders on the cooling-amber
  banner (`tone="warning"`, `App.jsx:155`), matching the `COOLING` pill on the same
  screen. `05-one-bound.png`: "Wallet bound. It is now your verified Ethereum
  wallet." stays verify-green (`tone="success"`, `App.jsx:154`). Both name the
  chain. Green is again exclusive to active.
- **Finding 3 (LOW) — sub-AA `--faint` em-dash → RESOLVED.** `--faint` darkened to
  `oklch(0.55 0.014 250)` (`tokens.css:17`) and the registry placeholder dash moved
  to `text-muted` (`Ledgers.jsx:62,64`, `--muted oklch(0.48 0.014 250)`, ≈5.7:1 on
  paper). `--faint` is now referenced by no text node at all (grep of `src/`), so
  the sub-AA path is gone twice over. Visible as the muted Solana `—` in
  `05-one-bound.png`.
- **Finding 4 (LOW) — guilloché in the reserved accent → RESOLVED by documented
  exception.** The author's-call option was taken: `RecordHeader.jsx:47` keeps
  `text-verify`, and `DESIGN.md:39–41` now records the guilloché as "the
  issued-document mark … the one non-state use the accent is permitted." Recorded,
  so it is not re-flagged.
- **Finding 5 (LOW) — Privy modal hardcoded light → RESOLVED (code).**
  `wallet/index.jsx:46` derives `theme` from
  `document.documentElement.dataset.theme` at provider mount. Not screenshot-able
  without an app id; the light-theme literal is gone.

### Other applied changes — landed

- **Signed message rebuilt (`backend/verify.py:30–57`) → landed.** Origins derive
  from `PUBLIC_URL` (`URI`/`DOMAIN`), so the message reads `localhost:5173` — the
  address bar, not `127.0.0.1:8000`. Confirmed in `04-attestation.png` /
  `06-cooling-380px.png`. Sentence-boundary line breaks, the "This binding will be
  listed in the public registry." consequence line, and the "Expiration Time" line
  are all present in the render.
- **Dialog copy / interaction (`AttestationDialog.jsx`) → landed.** Reassurance
  bullets merged to three, the public-record consent bullet added (`:44`);
  test-key description is conditional (`:33–35`); the error alert carries recovery
  guidance (`:62–71`) — seen in `07-error.png` ("… request a fresh one and try
  again."); the dead test-key path offers **Get a fresh message and retry**
  (`:74–77`, visible in `07-error.png`) instead of a dead loop; **Cancel** is
  disabled only while `binding`, operable during `signature-pending` (`:93`).
- **Smaller items → landed.** residenceStatus renders in default ink not accent
  (`IdentityRecord.jsx:32`; `05-one-bound.png`); ledger + card say "cooling" not
  "pending" (`Ledgers.jsx:29`, `ChainRecord.jsx:67`); test-key bindings carry a
  server-recorded "test key" marker (`Ledgers.jsx:21–23` on `proof_method ===
  'dev-test-key'`); `fmt` includes the year (`ChainRecord.jsx:16`; "Jul 24, 2026,
  05:13 PM"); cooling shows "— in about N hours" (`ChainRecord.jsx:72`;
  `06-cooling.png`); theme toggle labels the destination "Dark theme" / "Light
  theme" (`RecordHeader.jsx:35`; `05-one-bound-dark.png` reads "LIGHT THEME"); chain
  titles are `h3` (`ChainRecord.jsx:107,178`); the multi-wallet `select` uses
  `border-rule-strong` (`ChainRecord.jsx:128`); `CopyValue` has a persistent
  `aria-live` region and per-value `aria-label` (`CopyValue.jsx:19,30`); wipe and
  skip-cooling are single-element two-step arms (`App.jsx:49–70`,
  `ChainRecord.jsx:29–50`); the skeleton carries an sr-only status
  (`App.jsx:35`); the mobile ledger `thead` is sr-only (`clip-path`) not
  `display:none`, keeping the header in the a11y tree while the body stacks
  (`app.css:110–119`); bind labels are "Bind this wallet" / "Bind a throwaway test
  key (dev)" with the test-key button as the `outline` variant
  (`ChainRecord.jsx:146,155–157`; `05-one-bound.png`).

### Not resolved / regressions

None. No applied item failed to land, and diffing the fresh screenshots against
pass one surfaced no regression in type, colour, spacing, hierarchy or state
legibility.

### Banned-pattern re-scan (REBUILD.md "Look" ban list) — clean

- **No purple/violet, no gradient, no glassmorphism/blur.** `grep` for
  `gradient|backdrop-blur|blur(` over `src/` returns nothing; the accent is the
  single green-teal (`--verify`), status is amber/red only.
- **No Inter/Roboto/system as a display face.** Source Serif 4 (display),
  Public Sans (UI), Spline Sans Mono (machine) load from `index.html:9`; the
  masthead 300/700 split renders in every state. The mock IdP's IBM Plex is a
  deliberate separate-party face (`02-biometric-prompt.png`), not the registry's.
- **No neon, mascot, marketing hero, pill-everything.** The signed-out state is a
  numbered ledger card, not a hero (`01-signed-out.png`).
- **Tinted OKLCH neutrals, never #000/#666.** All neutrals are OKLCH with small
  chroma on hue 95/250 (`tokens.css`); dark ground is `oklch(0.205 …)`, not pure
  black (`05-one-bound-dark.png`).
- **One accent, on identity/verification/active only.** Guilloché is the recorded
  exception (Finding 4).
- **Dark + light, AA, 380px, weight 300/700, ~3× size steps, mono for every
  machine value** — all still hold (see verified-good).

---

### Verified good — checked and correct, do not re-plough

- **Type system.** Source Serif 4 300 vs 700 split renders in the masthead
  ("One verified person," 300 / "one wallet." 700, `RecordHeader.jsx:38–41`);
  Public Sans for prose; Spline Sans Mono for every address, HMAC, nonce,
  timestamp and figure. Display 36px → label 11px is ~3.3×. No Inter/Roboto/
  system as a display face.
- **Accent discipline.** Green-teal appears only on: identity header band +
  `FAYDA VERIFIED` badge, HMAC serial, residence-status value, active wallet
  address + `ACTIVE SINCE` + `Active` badge, and the primary verify CTA. Residence
  status is coloured uniformly (never branched — `IdentityRecord.jsx:32`), so it
  reads as an identity field, not a "citizen = good" stamp. No purple/violet
  anywhere.
- **Contrast (computed from tokens, both themes).** Every text-on-tint pair clears
  AA: body/muted 5.7–15.3 (light) / 6.6–14.6 (dark); active/pending/cancelled
  badges 6.65–8.84; primary button label (paper on verify) 6.33 / 7.56. Mock IdP
  page grays ≥4.99. The one pass-one exception (`--faint` em-dash) is closed —
  the dash now renders at `--muted` (≈5.7:1) and `--faint` is used by no text
  (pass-two finding 3). Every text node clears AA in both themes.
- **Destructive action confirmed.** `WipeButton` (`App.jsx:44–61`) is a two-step
  arm/confirm ("Wipe registry (dev)" → "Confirm: erase every identity and
  binding" + "Keep everything"). No single-click destroy.
- **Signing consent.** The dialog states what the signature does and cannot do
  ("proves you control this wallet … moves no funds and grants no spending
  permission … single-use and expires in five minutes"), plus the
  server-verifies-its-own-copy note and the live "wallet account changed"
  staleness block (`AttestationDialog.jsx:54–71`), plus the public-record consent
  bullet and origin-matched `PUBLIC_URL` message. The full message — address,
  Chain, Nonce, Issued At, Expiration Time — now renders at 380px as well as
  desktop (pass-two finding 1 closed); no inner scroll box on any width.
- **Copy affordance.** `CopyValue` is a real `<button>` — keyboard-reachable,
  copies on Enter/Space, transient "copied" feedback, shares the global focus
  ring, keeps `user-select:all`. Used for every address, HMAC and connected-wallet
  value. No truncation-without-copy.
- **Focus + motion.** Global `:focus-visible` = 2px `--verify` ring on all
  interactives incl. `<select>`, `<summary>`, theme toggle (`app.css:44`).
  `prefers-reduced-motion` kills all animation/transition (`app.css:49`); the one
  authored motion is `attest-rise`, an exponential ease-out (`cubic-bezier(0.16,1,
  0.3,1)`), not bounce/elastic.
- **State coverage.** Loading (`Skeleton`), empty (registry/history/not-bound),
  error (`BackendDown`, `OriginMismatch`, in-dialog signature failure, danger
  alert — no raw dumps), missing-config (`SetupConnector`), disconnected/stale
  (staleness guard), cooling, and an honest Solana-disabled state
  (`SOLANA_WALLETS_ENABLED = false`, explicit copy, never faked).
- **State distinguishable without colour.** Backend emits exactly
  `active/pending/archived/cancelled` (store.py:41); the badge handles all four
  with a text label inside each, so status survives greyscale.
- **380px.** Header wraps, `sm:grid-cols-2` collapses to one column, ledgers stack
  to label/value blocks via `data-label` (`app.css:110–124`), addresses
  `break-all`, no horizontal page scroll.
- **Privy isolation.** Every `@privy-io` import is confined to `src/wallet/`;
  embedded wallets off both chains; EIP-6963 discovery; swap seam intact.
- **Containment.** One card level. Shaded sub-blocks (claims JSON, `.env` snippet,
  the attestation message exhibit) are unbordered `bg-surface` regions, not nested
  cards.
- **Tokens.** Single source in `tokens.css`, mapped into Tailwind `@theme`; no
  scattered hex; the only inline `style` is the Guilloché's dynamic SVG sizing
  (`Guilloche.jsx:21`), which is legitimate.
- **Mock IdP reads as a separate party.** `02-biometric-prompt.png`: IBM Plex on a
  dark ground, `SIMULATED CAPTURE — NO SENSOR READ` disclosure, fingerprint glyph,
  `MATCH` badges, `MOCK PROVIDER` footer — a formal handoff, not a toy.

---

### Note for next session

The token file is already authoritative and wired to `CLAUDE.md`/`DESIGN.md`, so
the close-out needed no new tokens file — the "extract values to one place"
requirement is already satisfied and the next session starts from it, not from
defaults. Of the pass-one deltas: `--faint` moved in `tokens.css` (finding 3);
the message-tone distinction is `App.jsx` logic carried on `setOk`, not a token
(finding 2); the guilloché stayed put and became a documented exception in
`DESIGN.md` (finding 4). All landed in pass two; nothing is left for a third pass.

---

### Designed or generated?

**Designed** — and after pass two, without the one caveat. The deciding detail:
the Source Serif 4 300/700 split in the masthead paired with the strictly enforced
Public-Sans-prose / Spline-Mono-machine split across all seven states, and a
semantic accent that appears only on identity, verification and active — never as
decoration (the guilloché is now a colour the system explicitly claims in
`DESIGN.md`, not an arguable leak). A generated template picks one weight, one
family, and tints every status the same; this one drew those distinctions and held
them under stress, down to on-tint ink tokens that keep every badge above AA and a
success/pending banner that now takes its colour from the outcome it reports. The
one real pass-one defect — the clipped signing message at 380px — is fixed: the
mobile-first user now reads the full attestation, address and nonce included,
before authorising anything. Close-out: this is designed, not generated.
