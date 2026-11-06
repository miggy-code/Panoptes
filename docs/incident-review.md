# Review a retained evaluation-lab trial

Use the existing lab evidence; no model call or experiment rerun is needed.
The November 5 report, `ARCHITECTURE-RESULTS-2026-11-05-rerun.md`, lives in the
evaluation-lab workspace. Its raw run was retained at `/tmp/hermes-exp3/run-v2`
when this walkthrough was checked. Substitute the protected retained location
if it has moved; `/tmp` is not durable storage.

## Open the evidence

From a Python environment with Panoptes installed:

```bash
trial=/tmp/hermes-exp3/run-v2/trial-0064
panoptes verify --db-path "$trial/evidence/audit-snapshot.sqlite"
```

This checks local chain integrity without migrating or writing the database.
It does not prove complete capture, source truth, or independent checkpoint
custody. Lab artifact hashes and Panoptes hash-chain verification serve different
purposes; neither establishes a cryptographic inclusion proof for an arbitrary
selection of events.

The following reads the saved assessment and selects a recorded tool proposal
when present, otherwise a model request. It prints that event's exact session
and related evidence, not every session in the trial:

```bash
python - "$trial" <<'PY'
import json
from pathlib import Path
import sys

from panoptes.cli import main
from panoptes.db import AuditDB

trial = Path(sys.argv[1])
manifest = json.loads((trial / "manifest.json").read_text())
print(json.dumps({
    "saved_audit_complete": manifest["audit"]["complete"],
    "saved_audit_limitations": manifest["audit"]["limitations"],
    "saved_grade_passed": manifest["grade"]["passed"],
    "saved_executed_tool_calls": manifest["trajectory"]["executed_tool_calls"],
    "saved_trial_limitations": manifest["limitations"],
}, indent=2))

path = str(trial / "evidence" / "audit-snapshot.sqlite")
db = AuditDB.open_readonly(path)
try:
    anchor = next(db.iter_events(event_type="tool_call"), None)
    if anchor is None:
        anchor = next(db.iter_events(event_type="model_request"), None)
finally:
    db.close()
if anchor is None:
    print("No recorded tool proposal or model request; inspect the lab limitations.")
else:
    main(["session", anchor["agent"]["session_id"], "--db-path", path])
    main(["evidence", anchor["event_id"], "--db-path", path])
PY
```

Trial 65 is the report's one-based trial number: its directory is `trial-0064`,
as recorded in `recovery.json`. Its saved trajectory reports an explicit empty
execution list, and its snapshot contains no `tool_call` event. The adjacent
`trial-0065` is a different trial with a recorded tool call. Generally, a model
proposal is not proof of a local execution. A client-reported
result, a Hermes host-reported lifecycle event, and another producer's
`agentgate.*` event also carry different evidence boundaries. Missing capture
metadata on another producer's event is not automatically failed capture.

Use `exchange=` and `correlation=` to match recorded references to the lab's
`evidence/shim.jsonl`; use `call=` and native lifecycle references with the lab's
execution/attribution evidence. These values assert relationships; they do not
authenticate identities or establish causality. The lab's `capture/reconcile.py`
already performs the independent-journal checks. Do not reconstruct eligibility
from the displayed timeline alone.

## Preserve the interpretation

Trial 65's original manifest predates its post-hoc eligibility reassessment.
Read the run's `recovery.json` alongside `summary.json`: it records the original
and reassessed eligibility, retained manifest hash, source changes, reason, and
spend. The results report discloses that decision. A saved task pass, an explicit
zero-tool result, and verified use of the assigned architecture are separate
claims; zero tool use was included as off-treatment, not evidence its mechanism
ran. These historical assessments are not a fresh pass under today's gates.

For a specialist example with child attribution, repeat the read-only steps on
`trial-0001` and consult its saved `attribution` and native child evidence. A
session query is scoped to that exact session; a run filter likewise does not
automatically include children. The lab report supplies the trial-wide view.

`evidence` shows same-session related records chosen by call/run references, or
nearby turns/timestamps as a fallback. It is an investigation aid, not a causal
trace or cryptographic proof. `session --limit N` selects the newest N events
and states selected/matching counts; `--json` preserves full stored records and
selection counts. Counts and selection use separate reads on a live database.

Keep raw artifacts in protected storage. Follow the evaluation-lab README's
"Offline scheduling and artifact bundles" workflow (`experiment_bundle.py`)
for reviewed report artifacts and explicit raw-evidence references. It does not
automatically archive those references. No lab data needs to be copied into the
Panoptes package or its tests.
