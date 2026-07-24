# PROGRESS

The loop's memory. The agent forgets between runs; this file does not.
Update as work completes. Do not delete history, move items to Done.

Status: todo / doing / blocked / review / done

---

## Now

### M4 - New pending index aborts startup on a DB that already hit M2
**Status:** todo
**Severity:** medium (auditor finding, 2026-07-24, from the M2 fix review)
**Why:** ux_pending_chain_address is created with CREATE UNIQUE INDEX IF NOT EXISTS,
which is evaluated against existing rows. A database that suffered M2 before the fix
still contains two pending rows on one (chain, address); index creation then raises
IntegrityError inside store.init() at import time and the app refuses to boot. For
exactly the population the fix targets, this trades a per-read 500 for a hard-down.
Irrelevant to fresh/throwaway DBs, which is why t.py passes.

**Do:**
- Before creating the index, cancel duplicate pending rows (keep the oldest per
  (chain, address), cancel the rest) as a one-time cleanup in init()
- Test: plant duplicate pendings in a DB without the index, re-init, assert boot
  succeeds and the duplicates are cancelled

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
  hex is case-insensitive. Normalise per chain. Auditor note (2026-07-24): the unique
  indexes (active tier and the new pending tier) are case-SENSITIVE while the app
  check lowercases, so case-variant EVM addresses can slip both — normalising at
  write time fixes the index gap too.
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

### M2 - Cross-identity pending race wedges the registry - resolved 2026-07-24
Was: ux_pending_identity_chain scoped per-identity let two identities hold pending
bindings on one address; promotion then raised IntegrityError inside promote_due,
which runs on every /api/me and /api/registry read → permanent 500 for everyone.
Fix: (1) new partial unique index ux_pending_chain_address on (chain, address)
WHERE status='pending' closes the pending-vs-pending race at the DB layer;
(2) promote_due wraps each promotion in a SAVEPOINT — on IntegrityError it rolls
back (the loser's incumbent stays active) and cancels the conflicting pending row
so it never re-detonates. Tests 15 and 16 in t.py: 15 plants the un-indexable
active-vs-pending raced state and asserts reads stay 200, the loser is cancelled,
and both incumbents survive (verified to fail with a wedged 500 against pre-fix
store.py); 16 asserts the index rejects a duplicate cross-identity pending.
Auditor review of the diff: 0 new criticals, 0 new highs; one new medium (M4,
migration hazard on already-wedged DBs) and one low folded into L2.

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
