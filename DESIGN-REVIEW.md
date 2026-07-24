# Design review — Fayda wallet registry frontend

Method: rendered states in `screenshots/` diffed against the visual language in
`frontend/src/tokens.css` and CLAUDE.md. Two-pass process; this is pass one.
Report only — no files changed except this one.

---

## 2026-07-24

Reviewed all seven states at desktop and 380px. The frontend is deliberately
authored, not defaulted — the findings below are drift and edge-case breakage,
not a rebuild. Grouped by severity.

### Pass 2 — verification (2026-07-24)

Close-out of the two-pass process. Re-rendered every state (desktop + 380px) in
`screenshots/` and read the code where a screenshot cannot show the change
(focus ring, keyboard copy, token wiring). All ten pass-one findings land.
Privy modal states stay uncapturable (no app id) — unchanged, pre-noted gap.

| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | Contradictory success banner on error | **Resolved** | `App.jsx` `run()` 37–38 now `setErr(''); setOk('')`. `07-error.png` + `07-error-380px.png` show the red banner alone — no stacked green. |
| 2 | History table clips ACTIVATES at 380px | **Resolved** | `app.css` 223–238 `@media(max-width:420px)` stacks `.stacking-table` to label/value blocks via `td::before { content: attr(data-label) }`; `components.jsx` 224/231–235 supply `data-label`. `07-error-380px.png` shows CHAIN/ADDRESS/STATUS/REQUESTED/ACTIVATES as full rows, activation time intact. |
| 3 | Amber/red pill text sub-AA | **Resolved** | `tokens.css` 26–27 `--amber-ink #8A5A02`, `--red-ink #A32A20`; `app.css` 124/126 `.p-pending`/`.p-cancelled` consume them. `--amber`/`--red` retained for borders on paper. COOLING + PENDING pills in `07-error.png` read as dark amber, ≈4.9:1. |
| 4 | IdP dark page two sub-AA tiers | **Resolved** | `mock_esignet.py` 184 `.pmeta #8B95A3`, 186 `.foot #7E8794`. `02-biometric-prompt.png`: FIN/region/status line and MOCK PROVIDER footer both legible on the dark ground. |
| 5 | Addresses not keyboard-operable | **Resolved** | `components.jsx` 21–39 `CopyValue` is a `<button>` — reachable by Tab, copies on Enter/Space via `navigator.clipboard`, `aria-live` "copied" feedback (94–102), shares `button:focus-visible` ring (`app.css` 57), keeps `user-select:all` for mouse/touch. Used for every address (57, 109, 122, 153). |
| 6 | Inline style literals off the token scale | **Resolved (one residual)** | 14 of 15 literals migrated to `.stack`/`.stack-sm`/`.divider`/`.chain-name`/`.wallet-select`/`.cell-addr` (`app.css` 206–218); `App.jsx` carries none. **Residual:** `components.jsx:76` still `style={{ marginBottom: 0 }}`. Current: inline literal. Replacement: a `.flush-b { margin-bottom: 0 }` utility (mirrors `.flush`) on that `<p>`. Cosmetic, not a regression. |
| 7 | Disabled Reset shows pale-red signed out | **Resolved** | `App.jsx` 183 gates on `me.dev && me.authenticated`. `01-signed-out.png` shows Refresh only — no pink control. |
| 8 | Colour/elevation literals outside tokens | **Resolved** | `tokens.css` 28–30 add `--err-ink #7A2119`, `--ok-ink #12563A`, `--card #FFFFFF`; `app.css` `.card` (70), `.err` (163), `.ok` (172) reference them. No bare hexes left in those rules. |
| 9 | `<select>` outside focus-visible rule | **Resolved** | `app.css` 57 selector now includes `select:focus-visible` → 2px blue ring, matching buttons/links. |
| 10 | Capture glyph reads as wifi | **Resolved** | `mock_esignet.py` 198–204 redrawn as six nested ridge-loop paths around a core; `02-biometric-prompt.png` reads as a fingerprint. The amber dashed line (206) now scans across the ridges rather than radiating — reinforces the SIMULATED CAPTURE label. |

No regressions introduced by any fix. The `.addr` button inherits the global
`button` reset but is explicitly stripped back (`app.css` 76–92: no border,
no padding, `background:none`, `cursor:copy`) so it renders identically to the
prior `<div>` while gaining focus and keyboard copy — verified against
`05-one-bound.png` and `07-error.png`.

### HIGH

**1. Error state shows a contradictory success banner stacked on the error.**
Screenshot: `07-error.png` (top of page). The red `proof of control failed:
signature does not match address` sits directly above a green `Replacement
accepted. Activates in 72h`. The two statements contradict each other and both
claim to describe the last action.
- Cause: `App.jsx` `run()` (lines 34–46) clears `setErr('')` at line 35 on every
  action but never clears `ok`. A stale success from a prior action survives into
  the next action's failure. `ok` only clears on its 6s timeout (lines 28–32).
- Current: `run()` starts with `setErr(''); setBusy(true)`.
- Replacement: add `setOk('')` alongside `setErr('')` at the top of `run()` so a
  new action clears both banners before it resolves. This is the one state the
  brief explicitly asked to see, and it currently reads as two mutually exclusive
  outcomes at once.

### MEDIUM

**2. Binding-history table clips its most important column at 380px.**
Screenshots: `06-pending-cooling-380px.png`, `07-error-380px.png`,
`05-one-bound-380px.png` (BINDING HISTORY block). The 5-column table overflows
the viewport; the `ACTIVATES` header renders as `ACTIV` and the activation
timestamp (`Jul 27, 02:53 PM`) is sliced off at the container's right edge. For a
pending/cooling binding, *when the replacement goes live* is the single datum a
user is on this screen to read, and it is the one being cut.
- Cause: `app.css` line 178 `.table-card { padding: 0; overflow: auto; }` — the
  table (`components.jsx` HistoryTable, lines 198–221) scrolls horizontally but
  gives no scroll affordance and truncates silently, and the mono address column
  wraps to ~6 lines which crowds the row further.
- Current: fixed 5-column table at all widths.
- Replacement: at `≤420px` render each binding as a stacked label/value block
  (Chain, Address, Status, Requested, Activates as rows) instead of a horizontal
  table — matching the `.label` + `.value` pattern already used in ChainCard. The
  Registry table (3 columns) survives 380px; History (5 columns) does not.

**3. Amber status pill text fails WCAG AA.**
Screenshots: `06-pending-cooling.png` (COOLING pill), `07-error.png` (PENDING
pill). `--amber #B07203` on `--amber-bg #FBF0DC` at 10.5px measures ≈3.5:1;
AA requires 4.5:1 for text this size. `--red #C13B2F` on `--red-bg #F7E4E2` is
also borderline at ≈4.3:1. Green passes (≈4.5:1).
- Current: `app.css` lines 101/103; tokens `--amber #B07203`, `--red #C13B2F`.
- Replacement: darken the pill *foreground* tokens for the pill context only —
  amber to ~`#8A5A02` (raises to ≈4.9:1 on the same bg) and red to ~`#A5302610`…
  i.e. ~`#A32A20` (≈5.2:1). Keep the `--amber`/`--red` tokens as-is for borders
  and left-rules where they sit on paper and already pass; add
  `--amber-ink`/`--red-ink` for on-tint text. Status colour is load-bearing here,
  so it has to clear AA, not sit under it.

**4. IdP dark page has two sub-AA text tiers.**
Screenshot: `02-biometric-prompt.png`. `mock_esignet.py`:
- line 186–187 `.foot` `#5C6673` on `#12161C` ≈3.1:1 — the `MOCK PROVIDER — not
  connected…` footer is barely legible. Raise to ~`#7E8794` (≈4.6:1).
- line 184 `.pmeta` `#7E8794` on the `#1B212A` card ≈4.2:1 — the `FIN … · region
  · status` line is just under AA on the cards. Raise to ~`#8B95A3` (≈4.9:1).
These are the resident metadata and provenance line; both should clear 4.5:1.

**5. Addresses are mouse/touch-selectable but not keyboard-operable.**
Screenshots: every signed-in state (blue `.addr` rows). `.addr` uses
`user-select: all` (`app.css` lines 73–79), so a mouse drag or mobile long-press
copies the full string — good — but the element is a non-focusable `<div>`, so a
keyboard-only desktop user cannot reach or copy it. The brief requires full
keyboard operation *and* that addresses be copyable.
- Current: `<div className="addr">…</div>`, no tabindex, no copy control.
- Replacement: render each address as a copy affordance — a `<button>`-wrapped or
  focusable element with an explicit copy action and the existing
  `:focus-visible` outline — rather than a select-all div. Addresses are never
  truncated (good), so this is purely the keyboard/copy gap.

**6. Inline style literals scatter design values off the token scale.**
`components.jsx` carries ~15 inline `style={{…}}` numbers — `marginTop: 15`
(line 31), `fontWeight: 700` (line 76), `marginTop: 13` (83), `marginTop: 7`
(86, 99), `marginTop: 11` (89), `marginTop: 15, paddingTop: 14, borderTop`
(92–93), `fontSize: 12` (123), `maxWidth: 260` (209), `maxWidth: 230/230`
(234–235), plus `App.jsx` line 129 `marginTop: 0`. The values 15/13/11/7 are off
the `--space-*` scale (4/8/14/22/44) and `700`/`12` duplicate token values. The
brief bans inline styles competing with the stylesheet and values scattered as
literals — this is exactly that drift.
- Replacement: move these to classes in `app.css` referencing `--space-*` /
  `--strong-weight` / `--data-size`. `fontWeight: 700` on the chain label
  (line 76) should be a class, not an inline literal that bypasses the token.

### LOW

**7. Disabled "Reset everything" renders as pale red on the signed-out screen.**
Screenshot: `01-signed-out.png` (bottom). It is the only colour on an otherwise
ink-on-paper screen and, faded to `.35` opacity in destructive red, reads like a
soft error rather than a disabled dev control.
- Current: `App.jsx` 180–187 renders the dev reset whenever `me.dev`, disabled
  when `!me.authenticated`.
- Replacement: gate it on `me.dev && me.authenticated` so it is absent, not
  disabled-pink, before sign-in.

**8. Colour and elevation literals live outside tokens.**
`app.css`: `.card { background: #fff }` (line 70 — pure white cards sit on
`--paper #FBFBF9`; the 1-step lift is intentional but the value is a literal),
`.err` text `#7A2119` (line 140), `.ok` text `#12563A` (line 149). CLAUDE.md
points at `tokens.css` as the single source; these three, plus the magic spacing
from finding 6, should be migrated in as `--card`, `--err-ink`, `--ok-ink`.

**9. `<select>` and `<details>` fall outside the focus-visible rule.**
`app.css` line 57 scopes `:focus-visible` to `button, a, summary`. The wallet
picker `<select>` (`components.jsx` 119–128) and the claims `<details>` get only
the browser default ring. Add `select` (and rely on `summary` for details) to the
focus-visible selector for a consistent 2px blue outline.

**10. The simulated-capture glyph reads as a wifi/broadcast icon.**
Screenshot: `02-biometric-prompt.png`. The SVG (`mock_esignet.py` ~line 196–204)
next to `SIMULATED CAPTURE — NO SENSOR READ` is arcs + a dashed line — ambiguous
between a fingerprint and a signal icon. The amber label carries the meaning; the
glyph does not reinforce it. Minor — a fingerprint-ridge or face silhouette would
tie the icon to the copy.

---

### Verified good — checked and correct, do not re-plough

*(Pass 2 additions, now confirmed correct and not to be re-ploughed:)*

- **Token file is now the single source.** `tokens.css` carries all colour,
  type, and spacing values including the pass-one additions (`--amber-ink`,
  `--red-ink`, `--err-ink`, `--ok-ink`, `--card`). `app.css` references them; no
  bare hex or off-scale spacing literal survives except the one noted in finding
  6. The "extract into a tokens file" note from pass one is **done** — CLAUDE.md
  already points here.
- **Address copy affordance.** `CopyValue` is one composed component reused for
  every address/hash — no copy-paste variants — with focus ring, keyboard copy,
  and transient "copied" confirmation. Truncation-without-copy is gone; addresses
  remain full-length and selectable.
- **Responsive history.** The 5-column table degrades to stacked blocks below
  420px instead of clipping; the 3-column registry table survives unchanged. The
  one datum the cooling screen exists to show (ACTIVATES) is legible at 380px.
- **Focus coverage.** `button, a, summary, select` all carry the 2px blue
  `:focus-visible` ring; `<details>` is covered via `summary`. Every interactive
  element is reachable and visibly focusable.
- **Error state is now unambiguous.** A failed action clears any prior success
  before resolving, so `07-error.png` shows exactly one banner describing the
  last action.

---

### Verified good — from pass one, unchanged

- **Type system.** IBM Plex Sans / Mono split is consistent and semantic: every
  hash, address, FIN, nonce, timestamp and figure is mono; prose is sans. The h1
  weight contrast is real (200 hairline `Fayda identity →` against 700
  `wallet registry`) at 34px — an extreme jump, not a 400/600 hedge. h2 section
  rules are mono uppercase over a 2px ink border. This is an authored scale.
- **Palette discipline.** Ink `#12161C` on paper `#FBFBF9`, tinted neutrals
  (`--muted #5C6169`, not `#666`; no pure `#000`). Blue `#1F4E79` reserved for
  addresses/identity. One dominant, one accent. No purple/violet anywhere.
- **No template tells.** No hero section, no gradient depth, no rounded icon above
  a heading, no bounce/elastic motion, no cards nested inside cards (one level of
  containment throughout).
- **State distinguishable without colour.** Every pill carries a text label
  (Active / Cooling / Pending / Not bound / Archived / Cancelled) in addition to
  its tint, so status survives greyscale. History rows echo the same labels.
- **Signing message.** `04-signing-panel.png`: full server message shown in
  `.msgbox` with `white-space: pre-wrap`, no `max-height`, no scroll trap — the
  user can read the entire thing they are authorising. Exactly per spec.
- **Addresses not truncated.** Shown in full with `word-break: break-all`
  everywhere; `user-select: all` makes them mouse/touch-copyable (keyboard gap
  noted in finding 5).
- **`prefers-reduced-motion`** honoured (`app.css` 180–182); the only transitions
  are 0.12s opacity/border, no motion to suppress beyond that.
- **Muted body text** `#5C6169` on white ≈6.2:1 and green pill ≈4.5:1 both clear
  AA.
- **IdP page reads as a separate party.** `02-biometric-prompt.png`: the dark
  `#12161C` theme, `FAYDA · ESIGNET · NATIONAL ID` eyebrow and
  `Biometric verification — simulated` framing read as the national IdP, distinct
  from the paper-white registry, and the amber `SIMULATED CAPTURE — NO SENSOR
  READ` card plus `MOCK PROVIDER — not connected to the national register` footer
  keep it honest without reading as a toy. (The persona descriptions such as
  "Second identity, for testing the sybil constraint" expose seed intent, but
  that is acceptable for an internal PoC.)

---

### Note for next session

`tokens.css` already exists and CLAUDE.md already points at it — good. Finish the
job: the literals in findings 6 and 8 (inline spacing `15/13/11/7`, `#fff` card
fill, `#7A2119`/`#12563A` banner ink, and the new `--amber-ink`/`--red-ink` from
finding 3) should all land in `tokens.css` so the next pass starts from tokens
and does not re-derive these by hand.

---

### Designed or generated?

**Designed** — and after pass two, designed all the way down to the token file.
The deciding detail is unchanged: the hairline-200 / bold-700 split in the h1
paired with the strict rule that every cryptographic value renders in mono while
prose stays sans — a template picks one weight and one family and calls it clean;
this made a semantic choice and enforced it across seven states. Pass two
confirms the discipline holds under stress: the on-tint ink tokens
(`--amber-ink`/`--red-ink`) that keep status pills at AA are a distinction a
generated UI never draws — it would tint the pill and move on. Both passes are
now closed; no third pass warranted.

---

### Close-out (Pass 2, 2026-07-24)

Two-pass process complete. All ten pass-one findings resolved; one cosmetic
residual (finding 6, `components.jsx:76` inline `marginBottom:0`) logged for the
next incidental edit, not worth a dedicated pass. No regressions. The tokens
file is authoritative and wired to CLAUDE.md — the next session starts from
tokens, not defaults.
</content>
</invoke>
