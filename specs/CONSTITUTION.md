# pktflow Specs Constitution

**Version 1.0.0 — Ratified 2026-07-07**

Governs the relationship between [`specs/`](README.md) and the code in `crates/`. Every
contributor (human or agent) planning or reviewing a change to this repository is bound by
it. Where this document and a habit or a PR template disagree, this document wins.

## Preamble

The spec tree is not documentation written after the fact — it is the plan the code is built
against. `specs/` is normative; `crates/` is its realization. A behavior that exists in code
but not in a spec is undocumented debt. A spec that describes behavior the code no longer has
is a lie. Neither state is allowed to persist past the PR that created it.

---

## Article I — Spec Precedes Code

No sub-task's behavior may be implemented before its spec file exists with a filled-in
**Goal**, **Specification**, and **Acceptance criteria** (the shape fixed by Article III).
"Filled in" means reviewable, not exhaustive — a spec may be terse, but it may not be a
placeholder or a title-only stub.

- A PR that implements behavior **must** name the spec file(s) it satisfies in its
  description.
- If a spec doesn't exist yet for the behavior being built, the spec commit(s) come first —
  either as an earlier PR, or as the first commits in the same PR, reviewed as a spec before
  the diff that implements it is read as code.
- Exploratory spikes are fine, but nothing spiked is merged to a long-lived branch until the
  spec catches up. A spike is throwaway until then.

## Article II — Specs Track Reality, in Both Directions

A merged PR that changes observable behavior — a new field, a changed default, a relaxed or
tightened invariant, a new CLI flag, a new plugin — updates the relevant spec file(s) in the
**same PR**. This cuts both ways:

- New/changed behavior with no spec update: the PR is incomplete, not "good with a
  follow-up."
- A spec describing behavior that was since removed or changed and never updated: fix the
  spec at the next opportunity that touches that area; don't let a second lie compound the
  first.

When implementation surfaces that the spec was wrong (an edge case the author didn't
consider, a signature that doesn't compose), **the spec changes, not just the code** — update
the spec text in the same PR so the two never diverge, even briefly, in the merged history.

## Article III — Fixed Shape: Tasks, Sub-tasks, Checklists

The structural conventions already load-bearing in this tree are binding, not incidental:

- A numbered top-level folder (`NN-name/`) is a **task**: one `README.md` stating goal,
  dependencies, the sub-task checklist, and the task-level definition of done.
- A numbered file inside a task folder is a **sub-task spec**: `## Goal`, `## Specification`,
  `## Acceptance criteria` as a checkbox list. A task is done only when every sub-task's
  acceptance criteria are checked.
- A new capability fits into an existing task's next sub-task number, or — only when it's
  genuinely a new area of the system — becomes a new task folder with an entry added to the
  table and dependency graph in [`README.md`](README.md).
- Rust snippets in specs are shape sketches (names/signatures normative, bodies not) per the
  existing convention — a spec is not the place to paste the real implementation.

## Article IV — Traceability

Every sub-task spec cites what justifies it: the PRD requirement(s) it satisfies (`FR-#` /
`§#`) and any cross-cutting decisions it depends on (`D#`, see Article V). A spec whose
existence can't be traced to the PRD or an approved decision is a sign the PRD or
`DECISIONS.md` needs updating first — not that the spec should stand alone as its own
justification.

## Article V — Decisions Are Centralized

Cross-cutting or architectural calls — the kind that constrain more than one task — live as a
numbered entry in [`DECISIONS.md`](DECISIONS.md), not restated or (worse) re-litigated
piecemeal across sub-task files. Sub-task specs **cite** `D#`; they don't duplicate its
rationale.

- A new cross-cutting decision gets its `D#` entry in `DECISIONS.md` before, or in the same
  PR as, the specs that rely on it.
- Superseding a decision means editing the `D#` entry to say so explicitly (it stays,
  annotated) — it is not deleted or silently ignored by newer specs.

## Article VI — Acceptance Criteria Are the Only Definition of Done

A sub-task's checkboxes are the sole source of truth for "is this done." Consequences:

- A checkbox flips `[ ]` → `[x]` only in the PR that makes it genuinely true (code + test
  proving it), never speculatively ahead of the work, never left unchecked once the merged
  code already satisfies it.
- If an acceptance criterion turns out to be untestable, wrong, or superseded, edit the
  criterion itself (with reasoning, in the PR that discovers it) rather than checking it off
  on a technicality or quietly ignoring it.
- A task's own definition of done is derived — it is true exactly when every sub-task under
  it is checked. It is never marked complete "in spirit."

## Article VII — Specs Describe Shape, Not Proof

A spec commits to *what* must hold (interfaces, invariants, acceptance criteria) and cites
*why* (Article IV). It doesn't commit to *how* beyond the shape sketch needed to review it.
This keeps specs stable while implementations iterate, and keeps review of a spec change fast
— a reviewer is checking a contract, not a diff of generated code.

## Article VIII — Precedence Order

When two sources disagree, resolve in this order, highest first:

1. `PRD.md` (product intent)
2. `specs/DECISIONS.md` (ratified cross-cutting decisions)
3. The task `README.md` (task-level contract)
4. The sub-task spec file (specific contract)
5. Code comments / docstrings
6. Code itself

A conflict discovered anywhere in this order is a bug in the lower-precedence artifact, to be
fixed there — never resolved by treating the lower one as correct and leaving the higher one
stale.

## Article IX — Enforcement

`specs/` is reviewed like code: a PR that fails Articles I, II, or VI (missing spec, stale
spec, dishonest checkbox) is not mergeable regardless of what the implementation does. CI
(`just ci`) enforces the invariants specs *describe* (crate boundaries, lints, tests); it does
not and cannot enforce that the spec tree itself stayed honest — that responsibility belongs
to whoever writes and reviews the PR. Any invariant that becomes worth a CI gate is written
down as a spec/decision first, then wired into `just ci` — not the reverse.

## Article X — Amending This Constitution

This document versions independently of the project's crate versions, using semantic
versioning for governance changes:

- **MAJOR** — an article is removed, or its rule reverses (e.g. dropping spec-first).
- **MINOR** — a new article or a materially new rule is added.
- **PATCH** — wording, clarification, typo fixes with no behavioral change.

An amendment is itself a PR against this file: it states the version bump and reason in the
PR description, and updates the version/date line at the top. Ratified rules bind immediately
on merge; they are not retroactive to specs already merged under a prior version, but the
next touch to an older spec brings it into compliance.

---

## Compliance checklist (copy into a PR description)

- [ ] Spec file(s) for this behavior exist and are merged (Article I) — link them.
- [ ] Any behavior change is mirrored in the spec in this same PR (Article II).
- [ ] New/changed decision, if cross-cutting, has a `D#` entry (Article V).
- [ ] Acceptance-criteria checkboxes flipped match what this PR actually proves (Article VI).
- [ ] New spec cites its PRD `FR-#`/`§#` and any `D#` it relies on (Article IV).
