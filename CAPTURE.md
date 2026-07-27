# Capture flow spec (Sumsub-style identity verification)

Replace the mock's persona-picker with a real face + ID capture flow, mock ONLY
the final match (always passes), build identity from what's entered, PERSIST the
verified identity (so return = passkey login, never re-capture), DISCARD the images.

## Scope
Changes ONLY backend/mock_esignet.py and frontend VerifyGate.jsx + new capture
components. The real OIDC contract, /callback, SAFE_CLAIMS, RLS, R2 passkey login,
operator role, binding logic all stay. On mock-match success, issue the SAME OIDC
code + userinfo handoff the persona picker issued -- a realistic front door on the
mock, NOT a new auth path that bypasses OIDC. Whole flow stays gated behind
DEMO_MODE/dev; never mounts with a real Fayda provider. Capture replaces the
persona picker as the demo login.

## Verify-once, return-via-passkey
First-timer goes through capture; the resulting identity persists in Postgres as
identities already do. On return, R2 passkey login signs them in -- NOT through
capture again. If an identity already exists for the derived sub, route to passkey
login instead of re-verifying.

## Flow (Sumsub / Stripe Identity / Persona style)
1. Form: full name, birthdate, gender, region, residenceStatus toggle
   (CITIZEN / FOREIGN_NATIONAL -- the citizenship signal).
2. Live face capture via getUserMedia: feed, capture frame, show back, retake.
   Camera-denied -> designed upload-a-selfie fallback, not a crash.
3. ID document image upload with preview.
4. Review screen: captured face + ID side by side, MOCKED liveness + face-to-ID
   match, brief "verifying" that ALWAYS PASSES, clear pass result. Reads like a
   real KYC check (progress, liveness, decorative match score ok) with a small
   honest "simulated match -- no real biometric comparison" disclosure in dev.
5. On pass: mock issues its normal OIDC code; userinfo returns claims BUILT FROM
   THE FORM: name/birthdate/gender/region/residenceStatus as entered + a stable
   derived sub (hash of name+birthdate). Downstream unchanged.

## Hard constraints
- Face and ID IMAGES are NEVER persisted and NEVER leave the client except for the
  mock match (client-side or discarded immediately). No image byte reaches the
  session, any Postgres table, the access log, or any response. A stored face would
  be the most sensitive object in the system, inside the RLS/operator surveillance
  surface, and a special-category data-protection liability. The verification RESULT
  (identity) persists; the images do NOT. Add a test asserting no image bytes appear
  in the session, any table, the access log, or any response.
- Don't weaken any CLAUDE.md non-negotiable (FIN/sub, SAFE_CLAIMS, server-side
  sessions, RLS, passkey login).
- residenceStatus flows to the user's own view and is surfaced; FOREIGN_NATIONAL
  visibly differs from CITIZEN.
- Match the "modern classic" design language; every state designed: form,
  camera-loading, permission-denied, capturing, verifying, pass, retake,
  already-verified->passkey.

## Two properties of this mock, stated rather than assumed

**Whatever the person types IS the identity claim.** `sub` is a hash of name +
birthdate with no secret, so two people entering the same name and date of
birth land on the same identity row. That is not a bug introduced here — the
persona picker it replaces had the identical property, only cruder: anyone
could click "Meseret Alemu" and become her. What prevents it in the real system
is the biometric match against the national register, which is precisely the
step this mock simulates. It follows that **this flow is not an authentication
mechanism** and must never be reachable with a real provider configured; the
`MOCK_IDP`/`DEMO_MODE` gate and the boot refusal when real `FAYDA_*` variables
are present are what enforce that.

**The demo now collects real personal data.** The persona picker invented its
people; capture asks a live visitor for their actual name, date of birth,
gender, region and residence status, and persists them. The face and the ID do
not persist — that is the hard constraint above and it is tested — but the
typed details do, in a database with no retention policy, on a deploy anyone
can reach. Before this is shown to real users rather than colleagues, it needs
the same NBE/NIDP answer that B4 already asks for, plus a retention period and
a way for someone to have their record deleted. Recorded, not solved.

## Done when
- persona picker gone; capture drives first-time demo verification
- mock match always passes, looks like a real KYC check
- identity built from entered details, stable sub, correct residenceStatus, PERSISTS
- returning user logs in by passkey without re-capturing
- NO image byte ever persisted or returned (tested)
- camera-denied has a designed fallback
- flow only mounts under DEMO_MODE/dev
- backend/t.py passes, incl. no-image-persistence test AND return-user-skips-capture test
- auditor reports no new criticals or highs on the capture diff
