# DESIGN.md

The durable visual system for the Fayda wallet registry frontend. Tokens live
in frontend/src/styles/tokens.css — that file is the single source of values;
this file records the rules that make them a system.

## World

Digitized civil-registry document. The security-printed record — serials,
ruled ledger lines, a fine guilloché band, stamp-like status marks — carried
by modern web typography. Institutional gravity over decoration: the surface
should feel issued, not marketed.

## Type

- **Display:** Source Serif 4 — weight 300 for large display lines, 700 for
  the emphasized fragment. The 300/700 split inside one heading is the type
  signature. Never mid-weights for display.
- **UI/body:** Public Sans (civic provenance — USWDS). 400 body, 600 for
  in-card emphasis, 700 sparingly.
- **Machine values:** Spline Sans Mono for every address, hash, FIN-HMAC,
  nonce, timestamp, claim value, serial and figure. The mono/sans split is
  semantic: mono = machine/cryptographic, sans = prose. Never blur it.
- Scale: display 36px → section 13px mono-caps → body 15px → data 13px →
  label 11px caps. Steps between display and label ≈ 3×.

## Colour

OKLCH only. Tinted neutrals — never pure black, white, or gray-gray.

- Light: paper oklch(0.975 0.004 95), ink oklch(0.24 0.012 250).
- Dark: ground oklch(0.205 0.012 250), foreground oklch(0.93 0.006 95).
- **Accent (the only one):** Fayda green-teal oklch(0.46 0.085 175) light /
  oklch(0.72 0.10 172) dark. Spent exclusively on identity, verification and
  active state. If it appears on anything else, it is a bug.
- Status: cooling amber oklch(0.55 0.11 75), destructive red
  oklch(0.50 0.13 25) — semantic only, never decorative. On-tint text must
  clear AA 4.5:1.
- Recorded exception: the guilloché band renders in the accent. It is the
  issued-document mark — identity material, not decoration — and is the one
  non-state use the accent is permitted.
- Both themes ship. data-theme attribute wins over prefers-color-scheme.

## Structure

- The record header is the signature element: identity as an issued document —
  serial-styled HMAC, guilloché rule (inline SVG, subtle), residence status as
  a first-class field.
- Ledger tables: ruled horizontal lines, mono data, generous row height; they
  stack to label/value blocks under 420px.
- One level of containment. No cards inside cards. No modal except the
  attestation dialog, which exists because signing needs protected focus.
- Density of an operator tool; no hero, no marketing rhythm.

## Motion

One authored moment: the attestation dialog's entrance (fade + 4px rise,
exponential ease-out). Everything else is ≤120ms opacity/border. Reduced
motion collapses all of it.

## Copy

The interface explains what is cryptographically true, in the product's own
voice: "Signing proves you control this wallet. It moves no funds and grants
no permissions." Errors name the problem and the recovery. Dev-only surfaces
say so. Simulated things are labeled simulated.
