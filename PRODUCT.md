# PRODUCT.md

Inferred from REBUILD.md + CLAUDE.md under an autonomous run (no interview
possible); assumptions are labeled.

## What this is

A registry binding one Fayda-verified Ethiopian identity to at most one
self-custodied wallet per chain. The product takes no custody and holds no
keys; it stores cryptographic proof that a verified person controls an
address. Think civil registry, not crypto app.

## Audience

Ethiopian residents (mobile-first, often first wallet, often low crypto
literacy) binding a wallet to their national identity; secondarily operators
and partners inspecting the registry. ASSUMPTION: end users arrive via a
lending or payout product that requires a verified wallet, so the flow must
read as official and safe, not exciting.

## The job of this surface

Operate: complete the identity → wallet binding with full understanding of
what is being signed, and read the current state of one's record at a glance.
Trust is the conversion metric. The user must understand: signing proves
control, moves no funds, grants no permissions.

## Brand commitments (from the brief — binding)

- "Modern classic, not bonny": restrained, financial-grade, what a bank or a
  national registry would ship. Persuasion through institutional seriousness.
- No purple/violet gradients, glassmorphism, neon, mascots, marketing hero,
  pill-everything. Not a 2021 NFT mint page.
- Real typeface (not Inter/Roboto/system); weight contrast 300 vs 700; size
  steps 2–3×; monospace for every machine value.
- OKLCH tinted neutrals, never pure #000/#666; ONE accent reserved for
  identity/verification/active.
- Dark and light, WCAG AA, usable at 380px.
- Identity comes from Fayda; the wallet connector (Privy) is plumbing, never
  brand. The Fayda step presents like Stripe Identity/Persona: a formal
  verification handoff with an honest simulated-capture disclosure in dev.
- residenceStatus is surfaced prominently — it is the citizenship signal the
  product hinges on (value set unconfirmed with NIDP; display, never branch).

## Constraints

Backend contract is fixed (see REBUILD.md); same-origin via Vite proxy;
Privy free tier; no blockchain RPC anywhere; Solana wallet connection is not
enabled until external-wallet support is verified — honest disabled state.
