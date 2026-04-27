"""Tests for README.md formatting and structural changes introduced in this PR.

The PR replaced bare-text code blocks with fenced Markdown code blocks,
updated the secrets management section, added deployment documentation,
and updated the license section. These tests verify those structural
and content changes.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

README_PATH = Path(__file__).resolve().parents[1] / "README.md"


@pytest.fixture(scope="module")
def readme_text() -> str:
    return README_PATH.read_text()


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


def test_readme_file_exists() -> None:
    assert README_PATH.exists(), "README.md must exist"


def test_readme_is_not_empty(readme_text: str) -> None:
    assert len(readme_text.strip()) > 0


def test_readme_ends_with_newline() -> None:
    raw = README_PATH.read_bytes()
    assert raw.endswith(b"\n"), "README.md must end with a newline"


# ---------------------------------------------------------------------------
# Fenced code blocks: pipeline description
# ---------------------------------------------------------------------------


def test_pipeline_description_is_in_fenced_code_block(readme_text: str) -> None:
    """The pipeline diagram must be inside a fenced ```text block, not bare text."""
    # Find the fenced block containing the pipeline
    fenced_blocks = re.findall(r"```text\n(.*?)```", readme_text, re.DOTALL)
    pipeline_blocks = [b for b in fenced_blocks if "Input →" in b and "Audit Logging" in b]
    assert pipeline_blocks, (
        "Pipeline description (Input → … → Audit Logging) must be in a ```text fenced block"
    )


def test_pipeline_description_not_bare_in_prose(readme_text: str) -> None:
    """The old style had 'text Input → …' as raw prose; that must be gone."""
    # The old format started a line with literal 'text Input →'
    assert not re.search(r"^text\s+Input\s+→", readme_text, re.MULTILINE), (
        "Bare 'text Input →' prose found; pipeline must be in a fenced block"
    )


# ---------------------------------------------------------------------------
# System architecture diagram
# ---------------------------------------------------------------------------


def test_system_architecture_is_in_fenced_code_block(readme_text: str) -> None:
    """Architecture ASCII diagram must be in a ```text fenced block."""
    fenced_blocks = re.findall(r"```text\n(.*?)```", readme_text, re.DOTALL)
    arch_blocks = [b for b in fenced_blocks if "UI Layer" in b and "Audit Log" in b]
    assert arch_blocks, (
        "Architecture diagram must be in a ```text fenced block"
    )


def test_architecture_diagram_not_bare_prose(readme_text: str) -> None:
    """Old single-line 'text ┌───…' format must be gone."""
    assert not re.search(r"^text\s+.*┌", readme_text, re.MULTILINE), (
        "Architecture diagram must not appear as bare 'text ┌…' prose"
    )


# ---------------------------------------------------------------------------
# Repository structure block
# ---------------------------------------------------------------------------


def test_repo_structure_is_in_fenced_code_block(readme_text: str) -> None:
    fenced_blocks = re.findall(r"```text\n(.*?)```", readme_text, re.DOTALL)
    struct_blocks = [
        b for b in fenced_blocks
        if "app.py" in b and "requirements.txt" in b and "osint_core" in b
    ]
    assert struct_blocks, (
        "Repository structure must be in a ```text fenced block"
    )


# ---------------------------------------------------------------------------
# Local development instructions
# ---------------------------------------------------------------------------


def test_local_dev_instructions_in_bash_block(readme_text: str) -> None:
    bash_blocks = re.findall(r"```bash\n(.*?)```", readme_text, re.DOTALL)
    dev_blocks = [b for b in bash_blocks if "pip install" in b and "app.py" in b]
    assert dev_blocks, (
        "Local development instructions must be in a ```bash fenced block"
    )


def test_local_dev_uses_venv(readme_text: str) -> None:
    """Updated dev instructions must include virtualenv setup."""
    bash_blocks = re.findall(r"```bash\n(.*?)```", readme_text, re.DOTALL)
    dev_blocks = [b for b in bash_blocks if "pip install" in b and "app.py" in b]
    assert dev_blocks
    assert any(".venv" in b or "venv" in b for b in dev_blocks), (
        "Dev instructions must include virtualenv (venv) setup"
    )


def test_local_dev_includes_real_clone_url(readme_text: str) -> None:
    """Clone command must include the actual repository URL, not a placeholder."""
    bash_blocks = re.findall(r"```bash\n(.*?)```", readme_text, re.DOTALL)
    dev_blocks = [b for b in bash_blocks if "git clone" in b]
    assert dev_blocks, "A git clone command must be present in a bash block"
    assert not any("git clone <repo>" in b for b in dev_blocks), (
        "Clone URL must not be a placeholder '<repo>'"
    )
    assert any("github.com" in b for b in dev_blocks), (
        "Clone URL must reference the actual GitHub repository"
    )


# ---------------------------------------------------------------------------
# Deployment secrets documentation
# ---------------------------------------------------------------------------


def test_hf_token_documented_in_readme(readme_text: str) -> None:
    assert "HF_TOKEN" in readme_text, "HF_TOKEN secret must be documented"


def test_hf_username_documented_in_readme(readme_text: str) -> None:
    assert "HF_USERNAME" in readme_text, "HF_USERNAME secret must be documented"


def test_hf_space_name_documented_as_optional(readme_text: str) -> None:
    """HF_SPACE_NAME is an optional secret added in this PR."""
    assert "HF_SPACE_NAME" in readme_text, (
        "HF_SPACE_NAME optional secret must be documented in README"
    )


def test_deployment_flow_described(readme_text: str) -> None:
    """Deployment flow showing CI → sync pipeline must be documented."""
    text_blocks = re.findall(r"```text\n(.*?)```", readme_text, re.DOTALL)
    flow_blocks = [
        b for b in text_blocks
        if ("CI" in b or "main") and "Hugging Face" in b
    ]
    assert flow_blocks, (
        "Deployment flow (CI → Hugging Face) must be in a ```text fenced block"
    )


# ---------------------------------------------------------------------------
# Secrets management section
# ---------------------------------------------------------------------------


def test_secrets_management_mentions_github_actions(readme_text: str) -> None:
    """Updated section must mention GitHub Actions as secrets storage."""
    assert "GitHub Actions" in readme_text, (
        "Secrets management section must reference GitHub Actions repository secrets"
    )


def test_secrets_management_mentions_huggingface_space_secrets(readme_text: str) -> None:
    assert "Hugging Face Space Secrets" in readme_text or "Space Secrets" in readme_text


def test_no_credentials_committed_statement_present(readme_text: str) -> None:
    assert "No credentials" in readme_text or "credentials" in readme_text.lower()


# ---------------------------------------------------------------------------
# License section
# ---------------------------------------------------------------------------


def test_license_section_mentions_apache_2_0(readme_text: str) -> None:
    assert "Apache" in readme_text and "2.0" in readme_text


def test_license_section_links_to_license_file(readme_text: str) -> None:
    """License section must hyperlink to LICENSE file, not placeholder text."""
    assert re.search(r"\[LICENSE\]\(LICENSE\)", readme_text), (
        "License section must contain a Markdown link to the LICENSE file"
    )


def test_license_section_no_placeholder_text(readme_text: str) -> None:
    """Old placeholder 'Specify appropriate license' must be removed."""
    assert "Specify appropriate license" not in readme_text, (
        "Placeholder license text must be replaced with actual license info"
    )


# ---------------------------------------------------------------------------
# Risk categorisation block
# ---------------------------------------------------------------------------


def test_risk_categories_in_fenced_block(readme_text: str) -> None:
    text_blocks = re.findall(r"```text\n(.*?)```", readme_text, re.DOTALL)
    risk_blocks = [b for b in text_blocks if "LOW RISK" in b and "CONDITIONAL" in b]
    assert risk_blocks, (
        "Risk category list (LOW RISK / CONDITIONAL) must be in a ```text fenced block"
    )


def test_risk_category_bare_prose_removed(readme_text: str) -> None:
    """Old 'text LOW RISK …' inline prose must not appear."""
    assert not re.search(r"^text\s+LOW RISK", readme_text, re.MULTILINE), (
        "'text LOW RISK …' bare prose must be replaced with a fenced block"
    )


# ---------------------------------------------------------------------------
# Audit log format
# ---------------------------------------------------------------------------


def test_audit_log_format_in_json_block(readme_text: str) -> None:
    json_blocks = re.findall(r"```json\n(.*?)```", readme_text, re.DOTALL)
    audit_blocks = [
        b for b in json_blocks if "timestamp" in b and "indicator_hash" in b
    ]
    assert audit_blocks, (
        "Audit log JSON example must be in a ```json fenced block"
    )


# ---------------------------------------------------------------------------
# Sync badge removed
# ---------------------------------------------------------------------------


def test_outdated_sync_badge_removed(readme_text: str) -> None:
    """The 'Sync-setup' badge was removed in this PR."""
    assert "Sync-setup" not in readme_text, (
        "Outdated 'Sync-setup' badge must not appear in README"
    )


# ---------------------------------------------------------------------------
# Roadmap section
# ---------------------------------------------------------------------------


def test_roadmap_in_fenced_block(readme_text: str) -> None:
    text_blocks = re.findall(r"```text\n(.*?)```", readme_text, re.DOTALL)
    roadmap_blocks = [b for b in text_blocks if "v1.0" in b and "v2.0" in b]
    assert roadmap_blocks, "Roadmap must be in a ```text fenced block"