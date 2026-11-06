# Investigation friction: implementation record

Updated 2026-11-06. Miguel authorized existing-friction work and excluded OTel
bridge validation. This replaces the broader proposed plan.

## Evidence and scope

The evaluation lab already completed its 114-trial rerun. The recovered trial
65 is directory `trial-0064` (zero-based index 64); `trial-0065` is its neighbor. Retained manifests,
audit snapshots, reconciliation, attribution and recovery records supply the
investigation example. No synthetic demo or experiment rerun was necessary.

Read-only inspection of directories `trial-0065` and `trial-0001` found that `evidence` returned 11 and 23
related events respectively but printed only the anchor event ID in its heading.
Its separate summary-only renderer omitted execution boundaries and correlation
references; `session` also omitted exchange and correlation IDs from its text view.

## Implemented

- Reuse `_print_timeline_event` in `evidence`; remove its separate event formatter.
  Both views now show statuses, event/run/call/source IDs, execution labels,
  redacted bounded text and recorded inspection/truncation flags consistently.
- Add recorded exchange and correlation references to that existing renderer.
- Close the read-only evidence handle after selecting records and explicitly label
  correlation as insufficient proof of causality or execution.
- Add `docs/incident-review.md`, linked from README, using retained trial evidence
  and the lab's existing assessment/recovery/retention workflow.
- Extend the existing CLI test across both commands instead of adding another
  fixture or formatting test framework.

No new abstraction, command, schema, dependency, capture summary, lab import,
identity inference, or runtime service. OTel is unchanged and out of scope.

## Verification

The expanded CLI tests failed before implementation for the missing references
and evidence event IDs. Afterwards all 29 CLI tests passed. The documented
Python snippet ran against those retained snapshots: all 11 and 23 related event
IDs were visible, correlation/exchange references and execution labels appeared,
and each snapshot's SHA-256 remained unchanged. The final walkthrough also ran
against the recovered `trial-0064`, including its no-tool-call fallback. `git diff --check` passed.

Full suite: `.venv/bin/python -m pytest -q` passed all 516 tests in 39.70 seconds.
At that implementation checkpoint, no paid model calls, external backend
validation, commit, push, or remote CI run occurred. Tests cover both CLI views' ordering, references, execution boundaries,
inspection status, terminal escaping, redaction and unchanged database bytes.

## Remaining boundaries

The timeline does not replace independent capture reconciliation or grading.
Session filters do not include every trial identity, and related-event selection
can use a nearby-turn/time heuristic. Raw artifacts remain operator-managed;
`/tmp` is not durable storage. No new checkpoint-custody or capture-completeness
claim follows from this presentation improvement.


## 0.3.0 release follow-through

The release review found that null or missing counts in a reported cache-write
TTL split were dropped, allowing a guessed five-minute price. The parser now
marks that split invalid, including an empty split object. Regression cases cover
buffered and streamed replies; valid zero/nonzero splits and absent breakdowns
retain their existing behavior.

Validation before push: the expanded unreadable-split selection failed six cases
before the fix (10 passed), then passed all 16 after the fix. Pricing and CLI tests
passed all 96 cases. The full suite passed 563 tests on local Python 3.13;
`pip check`, `git diff --check`, an isolated distribution build and strict Twine
checks passed. This records local evidence; remote CI and publication are separate
release steps.
