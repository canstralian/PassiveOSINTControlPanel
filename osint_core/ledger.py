"""
osint_core.ledger
=================

Constraint ledger persistence for the Passive OSINT Control Panel.

The ledger records constraint decisions without raw indicators. It exists to
make pressure reusable as architecture: blocked actions, safe substitutions,
and repeated failure patterns become inspectable data.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .policy import enforce_audit_payload
from .scorecard import score_constraint_event
from .types import ConstraintEvaluation, ConstraintEvent


DEFAULT_CONSTRAINTS_DIR = Path("runs") / "constraints"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def validate_run_id(run_id: str) -> str:
    """Return a filename-safe run ID or raise ValueError."""
    candidate = str(run_id or "")
    if not RUN_ID_RE.fullmatch(candidate):
        raise ValueError("run_id must be 1-128 filename-safe characters: A-Z a-z 0-9 _ . -")
    return candidate


def event_to_dict(event: ConstraintEvent) -> dict[str, Any]:
    """Serialize a constraint event and include its scorecard disposition."""
    payload = asdict(event)
    payload["score"] = asdict(score_constraint_event(event))
    enforce_audit_payload(payload)
    return payload


def evaluation_to_dict(evaluation: ConstraintEvaluation) -> dict[str, Any]:
    """Serialize an evaluation without raw indicators."""
    payload = {
        "run_id": evaluation.run_id,
        "proposed_actions": [asdict(action) for action in evaluation.proposed_actions],
        "allowed_actions": [action.action_id for action in evaluation.allowed_actions],
        "blocked_actions": [action.action_id for action in evaluation.blocked_actions],
        "requires_approval_actions": [
            action.action_id for action in evaluation.requires_approval_actions
        ],
        "events": [event_to_dict(event) for event in evaluation.events],
    }
    enforce_audit_payload(payload)
    return payload


def write_constraint_ledger(
    evaluation: ConstraintEvaluation,
    *,
    directory: Path | str = DEFAULT_CONSTRAINTS_DIR,
) -> Path:
    """Write a constraint evaluation to `runs/constraints/<run_id>.json`."""
    output_dir = Path(directory).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_run_id = validate_run_id(evaluation.run_id)
    path = (output_dir / f"{safe_run_id}.json").resolve()
    if output_dir not in path.parents:
        raise ValueError("constraint ledger path escaped the output directory")

    path.write_text(
        json.dumps(evaluation_to_dict(evaluation), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def summarize_constraint_events(events: list[ConstraintEvent]) -> str:
    """Render events as compact Markdown for reports or UI panels."""
    if not events:
        return "_No constraint events recorded._"

    lines = ["## Constraint Decisions", ""]
    for event in events:
        score = score_constraint_event(event)
        lines.append(
            f"- **{event.original_action}**: `{event.decision}` via "
            f"`{event.constraint_id}` — {event.rationale} "
            f"Disposition: `{score.disposition}`."
        )
    return "\n".join(lines)
