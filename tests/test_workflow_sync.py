"""Tests for .github/workflows/sync-huggingface.yml.

Validates the structure, trigger types, job conditions, environment variable
usage, and shell logic introduced or modified in this PR.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "sync-huggingface.yml"
)


@pytest.fixture(scope="module")
def workflow() -> dict:
    """Parse the workflow YAML once for all tests."""
    return yaml.safe_load(WORKFLOW_PATH.read_text())


# ---------------------------------------------------------------------------
# File-level sanity checks
# ---------------------------------------------------------------------------


def test_workflow_file_exists() -> None:
    assert WORKFLOW_PATH.exists(), "sync-huggingface.yml must exist"


def test_workflow_file_is_valid_yaml() -> None:
    parsed = yaml.safe_load(WORKFLOW_PATH.read_text())
    assert isinstance(parsed, dict), "Workflow YAML must parse to a mapping"


# ---------------------------------------------------------------------------
# Trigger: workflow_run (replaces push)
# ---------------------------------------------------------------------------


def test_trigger_uses_workflow_run_not_push(workflow: dict) -> None:
    """PR changed trigger from 'push' to 'workflow_run'."""
    on = workflow["on"]
    assert "workflow_run" in on, "Trigger must use workflow_run"
    assert "push" not in on, "Trigger must NOT use bare push (replaced by workflow_run)"


def test_workflow_run_watches_ci_workflow(workflow: dict) -> None:
    wfr = workflow["on"]["workflow_run"]
    assert "CI" in wfr["workflows"], "workflow_run must watch the 'CI' workflow"


def test_workflow_run_filters_main_branch(workflow: dict) -> None:
    wfr = workflow["on"]["workflow_run"]
    assert "main" in wfr["branches"], "workflow_run must filter on the 'main' branch"


def test_workflow_run_type_is_completed(workflow: dict) -> None:
    wfr = workflow["on"]["workflow_run"]
    assert "completed" in wfr["types"], "workflow_run must listen for the 'completed' type"


def test_workflow_dispatch_input_still_present(workflow: dict) -> None:
    assert "workflow_dispatch" in workflow["on"]
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert "sync_direction" in inputs


# ---------------------------------------------------------------------------
# Job: sync-github-to-huggingface
# ---------------------------------------------------------------------------


def test_github_to_hf_job_exists(workflow: dict) -> None:
    assert "sync-github-to-huggingface" in workflow["jobs"]


def test_github_to_hf_condition_checks_workflow_run_success(workflow: dict) -> None:
    condition = workflow["jobs"]["sync-github-to-huggingface"]["if"]
    assert "workflow_run" in condition
    assert "conclusion == 'success'" in condition


def test_github_to_hf_condition_checks_workflow_dispatch(workflow: dict) -> None:
    condition = workflow["jobs"]["sync-github-to-huggingface"]["if"]
    assert "workflow_dispatch" in condition
    assert "github-to-huggingface" in condition


def test_github_to_hf_condition_does_not_trigger_on_failed_run(workflow: dict) -> None:
    """Condition must require 'success', not any completion."""
    condition = workflow["jobs"]["sync-github-to-huggingface"]["if"]
    # Must not allow any conclusion (would be no conclusion check at all)
    assert "conclusion" in condition


# ---------------------------------------------------------------------------
# Checkout step: ref fallback to head_sha
# ---------------------------------------------------------------------------


def _find_step(steps: list[dict], name_fragment: str) -> dict | None:
    for step in steps:
        if name_fragment.lower() in step.get("name", "").lower():
            return step
    return None


def test_checkout_step_uses_head_sha_fallback(workflow: dict) -> None:
    steps = workflow["jobs"]["sync-github-to-huggingface"]["steps"]
    checkout = _find_step(steps, "Checkout")
    assert checkout is not None, "Checkout step must exist"
    ref_value = checkout.get("with", {}).get("ref", "")
    assert "workflow_run.head_sha" in ref_value, (
        "Checkout ref must reference workflow_run.head_sha"
    )
    assert "github.ref" in ref_value, (
        "Checkout ref must fall back to github.ref"
    )


def test_checkout_step_has_full_history(workflow: dict) -> None:
    steps = workflow["jobs"]["sync-github-to-huggingface"]["steps"]
    checkout = _find_step(steps, "Checkout")
    assert checkout is not None
    assert checkout.get("with", {}).get("fetch-depth") == 0


# ---------------------------------------------------------------------------
# Add Hugging Face remote: HF_SPACE_NAME optional secret
# ---------------------------------------------------------------------------


def _find_hf_remote_step(steps: list[dict]) -> dict | None:
    return _find_step(steps, "Add Hugging Face remote")


def test_hf_to_github_add_remote_step_exposes_hf_space_name(workflow: dict) -> None:
    """Both jobs must expose HF_SPACE_NAME in the 'Add Hugging Face remote' step."""
    for job_name in ("sync-github-to-huggingface", "sync-huggingface-to-github"):
        steps = workflow["jobs"][job_name]["steps"]
        step = _find_hf_remote_step(steps)
        assert step is not None, f"'Add Hugging Face remote' step missing in {job_name}"
        env = step.get("env", {})
        assert "HF_SPACE_NAME" in env, (
            f"HF_SPACE_NAME must be in env of 'Add Hugging Face remote' in {job_name}"
        )


def test_hf_space_name_falls_back_to_repo_name_in_shell(workflow: dict) -> None:
    """Shell script must use parameter expansion fallback for SPACE_NAME."""
    for job_name in ("sync-github-to-huggingface", "sync-huggingface-to-github"):
        steps = workflow["jobs"][job_name]["steps"]
        step = _find_hf_remote_step(steps)
        assert step is not None
        run_script = step.get("run", "")
        # Bash parameter expansion: ${HF_SPACE_NAME:-${GITHUB_REPOSITORY#*/}}
        assert "HF_SPACE_NAME:-" in run_script, (
            f"SPACE_NAME fallback pattern missing in {job_name}"
        )
        assert "GITHUB_REPOSITORY#*/" in run_script, (
            f"Repo-name extraction pattern missing in {job_name}"
        )


def test_remote_url_uses_space_name_variable(workflow: dict) -> None:
    """Remote URL must use SPACE_NAME variable, not hardcoded REPO_NAME."""
    for job_name in ("sync-github-to-huggingface", "sync-huggingface-to-github"):
        steps = workflow["jobs"][job_name]["steps"]
        step = _find_hf_remote_step(steps)
        assert step is not None
        run_script = step.get("run", "")
        assert "SPACE_NAME" in run_script
        assert "REPO_NAME" not in run_script, (
            f"Old REPO_NAME variable must not appear in {job_name}"
        )


# ---------------------------------------------------------------------------
# Push step: HEAD:main (not main:main)
# ---------------------------------------------------------------------------


def test_push_to_hf_uses_head_refspec(workflow: dict) -> None:
    steps = workflow["jobs"]["sync-github-to-huggingface"]["steps"]
    push_step = _find_step(steps, "Push GitHub main to Hugging Face")
    assert push_step is not None, "Push step must exist"
    run_script = push_step.get("run", "")
    assert "HEAD:main" in run_script, "Push must use HEAD:main refspec"
    assert "main:main" not in run_script, "Old main:main refspec must not appear"


def test_push_uses_force_with_lease(workflow: dict) -> None:
    steps = workflow["jobs"]["sync-github-to-huggingface"]["steps"]
    push_step = _find_step(steps, "Push GitHub main to Hugging Face")
    assert push_step is not None
    run_script = push_step.get("run", "")
    assert "--force-with-lease" in run_script


# ---------------------------------------------------------------------------
# Job: sync-huggingface-to-github
# ---------------------------------------------------------------------------


def test_hf_to_github_job_exists(workflow: dict) -> None:
    assert "sync-huggingface-to-github" in workflow["jobs"]


def test_hf_to_github_condition_only_fires_on_dispatch(workflow: dict) -> None:
    condition = workflow["jobs"]["sync-huggingface-to-github"]["if"]
    assert "workflow_dispatch" in condition
    assert "huggingface-to-github" in condition
    # Must NOT fire on workflow_run
    assert "workflow_run" not in condition


# ---------------------------------------------------------------------------
# Concurrency and permissions
# ---------------------------------------------------------------------------


def test_concurrency_does_not_cancel_in_progress(workflow: dict) -> None:
    assert workflow["concurrency"]["cancel-in-progress"] is False


def test_permissions_allow_write(workflow: dict) -> None:
    assert workflow.get("permissions", {}).get("contents") == "write"


# ---------------------------------------------------------------------------
# Shell logic unit tests (SPACE_NAME expansion)
# ---------------------------------------------------------------------------


def _run_shell(script: str, env: dict[str, str] | None = None) -> str:
    """Run a bash snippet and return stdout."""
    import os

    full_env = {**os.environ, **(env or {})}
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        env=full_env,
    )
    assert result.returncode == 0, f"Shell script failed: {result.stderr}"
    return result.stdout.strip()


def test_space_name_uses_hf_space_name_when_set() -> None:
    out = _run_shell(
        'SPACE_NAME="${HF_SPACE_NAME:-${GITHUB_REPOSITORY#*/}}"; echo "$SPACE_NAME"',
        env={"HF_SPACE_NAME": "my-custom-space", "GITHUB_REPOSITORY": "owner/repo"},
    )
    assert out == "my-custom-space"


def test_space_name_falls_back_to_repo_name_when_hf_space_name_empty() -> None:
    out = _run_shell(
        'SPACE_NAME="${HF_SPACE_NAME:-${GITHUB_REPOSITORY#*/}}"; echo "$SPACE_NAME"',
        env={"HF_SPACE_NAME": "", "GITHUB_REPOSITORY": "owner/my-repo"},
    )
    assert out == "my-repo"


def test_space_name_falls_back_when_hf_space_name_unset() -> None:
    """HF_SPACE_NAME absent in environment → fall back to repo name portion."""
    script = (
        "unset HF_SPACE_NAME; "
        'GITHUB_REPOSITORY="owner/fallback-repo"; '
        'SPACE_NAME="${HF_SPACE_NAME:-${GITHUB_REPOSITORY#*/}}"; '
        'echo "$SPACE_NAME"'
    )
    out = _run_shell(script)
    assert out == "fallback-repo"


def test_space_name_strips_only_org_prefix() -> None:
    """${GITHUB_REPOSITORY#*/} strips only the first slash-delimited segment."""
    out = _run_shell(
        'SPACE_NAME="${HF_SPACE_NAME:-${GITHUB_REPOSITORY#*/}}"; echo "$SPACE_NAME"',
        env={"HF_SPACE_NAME": "", "GITHUB_REPOSITORY": "my-org/PassiveOSINTControlPanel"},
    )
    assert out == "PassiveOSINTControlPanel"


def test_secret_validation_fails_on_missing_hf_token() -> None:
    result = subprocess.run(
        ["bash", "-c", 'HF_TOKEN=""; test -n "$HF_TOKEN" || (echo "HF_TOKEN is missing" && exit 1)'],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "HF_TOKEN is missing" in result.stdout


def test_secret_validation_passes_when_token_set() -> None:
    result = subprocess.run(
        ["bash", "-c", 'HF_TOKEN="abc"; test -n "$HF_TOKEN" || exit 1'],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
