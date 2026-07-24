# PROGRESS

The loop's memory. The agent forgets between runs; this file does not.
Update as work completes. Do not delete history, move items to Done.

Status: todo / doing / blocked / review / done

---

## Now

### M2 - Cross-identity pending race wedges the registry
**Status:** todo
**Severity:** high (promoted from medium)
**Why:** ux_pending_identity_chain is scoped per-identity, so two identities can hold
pending bindings on the same address. When both cooling periods elapse, promote_due
hits the active-tier unique index and raises IntegrityError. Because promote_due runs
inside every /api/me and /api/registry read, the registry then returns 500 for
everyone, permanently, with no self-healing path.

**Do:**
- Scope the pending unique index across identities, not per-identity
- Catch IntegrityError inside promote_due so a conflicting row cannot wedge reads
- Test that reproduces the race and asserts reads stay healthy

### M1 - IntegrityError surfaces as 500 instead of 409
**Status:** todo
**Severity:** medium
**Do:** Wrap the INSERT in store.create_binding, translate IntegrityError to
HTTPException(409). Test the concurrent-bind path.

### R1 - Record wallet provenance and assurance level
**Status:** todo
**Why:** A signature from a self-custody wallet proves the user controls the key. From
a provider-held embedded wallet (Privy et al.) it proves the user authenticated to the
provider and the provider co-signed. Weaker claim, same shape. This registry exists to
assert "this verified human controls this address", so the distinction must be recorded
at bind time. It cannot be reconstructed later.

**Do:**
- Add wallet_source (external | embedded | custodial) and assurance_level
  (self_custody | provider_assisted) to wallet_bindings. Both NOT NULL.
- Existing rows migrate to external / self_custody.
- Surface in /api/me, /api/registry and the UI. Provider-assisted must be visually
  distinguishable.
- Tests asserting defaults and round-trip.

### R2 - Wallet provider interface
**Status:** todo
**Why:** Privy or equivalent is likely needed for farmer lending, where users have no
wallet and cannot manage a seed phrase. Adding it later should be additive.

**Do:**
- Extract a WalletProvider protocol. Current path becomes ExternalWalletProvider.
- Binding endpoint depends on the protocol, not a concrete provider.
- Do NOT integrate Privy. Documented seam only.

### L1-L4 - Deferred
- L1 auth_nonces never pruned. Add periodic delete.
- L2 Solana addresses compared case-insensitively. base58 is case-sensitive; only EVM
  hex is case-insensitive. Normalise per chain.
- L3 OIDC nonce generated but never validated. Dead scaffolding that reads as protection.
- L4 promote_due runs lazily on read. Should be a scheduled job.

---

## Blocked

### B1 - Real Fayda claim names
Blocked on partner credentials from partner.fayda.et. mock_esignet.py holds a
reconstruction. Do not build logic depending on a specific claim name outside that file.

### B2 - Citizenship check
Fayda proves residency, not citizenship. Foreign nationals resident in Ethiopia can hold
valid Fayda. Any citizens-only feature needs a separate mechanism. Open question for ECMA.

### B3 - Privy data residency
Privy is US-hosted and Stripe-owned since June 2025. Binding a Fayda-verified identity
to a wallet whose keys are partly held abroad is a question for NBE and NIDP under
Ethiopian data-protection rules. Unanswered. Do not integrate before it is.

---

## Done

### C1 - Raw FIN sent to the browser (critical) - resolved 2026-07-24
Whitelist at the callback boundary. Note the residual: name, birthdate, gender and
region still sit in a signed-not-encrypted cookie. FIN-specific invariant satisfied,
underlying unencrypted-PII issue unchanged.

### H1 - Unauthenticated dev_reset - resolved 2026-07-24
### H2 - fast-forward cooling bypass - resolved 2026-07-24
### H3 - Secret/pepper regeneration - resolved 2026-07-24
### N1 - APP_ENV defaulted open - resolved 2026-07-24
Default inverted to production so a forgotten env var fails closed.
### M3 - Dev surface unguarded - resolved as side effect of H1/H2/H3
