# Running this

Structured as a loop rather than a prompt, following Addy Osmani's
[loop engineering](https://addyosmani.com/blog/loop-engineering/) model: five
primitives plus on-disk state, with the maker kept separate from the checker.

## Setup

Drop these into the repo root:

```
CLAUDE.md                        project knowledge
PROGRESS.md                      state — survives between runs
.claude/agents/auditor.md        the checker
.claude/agents/design-critic.md  the frontend checker
```

Install the design skill:

```
/plugin marketplace add pbakaus/impeccable
```

Then, once, so it learns your project's design context:

```
/teach-impeccable
```

---

## Prompt 1 — Audit before you change anything

Run this first. Auditing code you just modified means auditing your own
assumptions.

```
Read CLAUDE.md and PROGRESS.md.

Use the auditor subagent to run a full adversarial security audit of this
codebase. Do not fix anything during the audit — report only.

Pay particular attention to the known suspects listed under R3 in PROGRESS.md.
Each one must be explicitly confirmed or cleared, not skipped.

Write findings to AUDIT.md. Then update PROGRESS.md: mark R3 done, and add any
critical or high finding as its own new task under Now.
```

---

## Prompt 2 — The revisions, with a stopping condition

`/goal` runs until a condition you wrote is actually true, and a separate model
checks whether it holds — so the agent that wrote the code is not the one grading
it. Give it something verifiable.

```
/goal Read CLAUDE.md and PROGRESS.md, then complete tasks R1 and R2.

R1: add wallet_source and assurance_level to wallet_bindings, surface them
through the API and the UI, migrate existing rows.

R2: extract a WalletProvider protocol so a future embedded-wallet provider is
additive. Do not integrate Privy — leave a documented seam.

Stop when all of the following hold:
  - python t.py exits 0 with every check passing
  - new tests exist covering both columns and the protocol seam
  - the migration runs clean against an existing registry.db
  - grep for the raw FIN returns no hits in any response body, log, or cookie
  - the UI visually distinguishes provider_assisted from self_custody

Update PROGRESS.md as each task completes.
```

---

## Prompt 3 — Frontend

```
Read CLAUDE.md, then use the design-critic subagent to review static/index.html.

Run Impeccable's /audit and /critique first and fold the results in. Write to
DESIGN-REVIEW.md.

Then fix only what the review names. Do not redesign anything it did not flag.
The visual language in CLAUDE.md is settled — you are correcting drift, not
starting over.
```

---

## Prompt 4 — Re-audit

The loop closes here. Everything above changed the code, so the earlier audit is stale.

```
Use the auditor subagent again against the current state. Compare to AUDIT.md.

Report: which findings are resolved, which remain, and which are new — anything
introduced by R1, R2 or the frontend pass. Append to AUDIT.md with today's date.

Update PROGRESS.md.
```

---

## If you want it running unattended

Once the above is clean, this is the recurring shape. Automations are the heartbeat
that turns a one-off into a loop:

```
Every morning: read PROGRESS.md, pick the top unblocked task under Now, open a
worktree, implement it, run the auditor subagent against the diff, and only mark
it done if the audit comes back clean. Write what happened to PROGRESS.md.
Anything you cannot resolve, add to Blocked with the reason.
```

Use `git worktree` or `--worktree` if you run more than one at a time, so parallel
agents do not collide on the same files.

---

## Two things worth keeping in mind

**"Done" is a claim, not a proof.** The maker/checker split is what makes the
loop's "it's done" mean something, and even then it is a claim. Read what the loop
produces. The faster it ships code you did not write, the wider the gap between
what exists and what you understand.

**The invariants in CLAUDE.md are the real spec.** An agent starts every session
cold and will fill any hole in your intent with a confident guess. Everything you
do not write down gets re-derived from zero each run, usually differently. When you
learn something new about Fayda or about what ECMA requires, it goes in CLAUDE.md —
not into a chat message that evaporates.
