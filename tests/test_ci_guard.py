"""Tests for scripts/ci_guard.py.

Each rule is exercised against a synthetic repository so the test suite does
not depend on the surrounding project layout. Tests assert on rule names and
finding paths, never on grep output strings.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from textwrap import dedent

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci_guard.py"


def _load_guard():
    spec = importlib.util.spec_from_file_location("ci_guard", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ci_guard = _load_guard()


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """Build a minimal passing repo skeleton."""
    (tmp_path / "osint_core").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "osint_core" / "intent.py").write_text("# intent\n")
    (tmp_path / "osint_core" / "policy.py").write_text("# policy\n")
    (tmp_path / "osint_core" / "validators.py").write_text("# validators\n")
    (tmp_path / "data" / "sources.yaml").write_text("domain:\n  - name: example\n")
    return tmp_path


# ---------- required_files ----------


def test_required_files_passes_when_all_present(fake_repo: Path) -> None:
    findings = ci_guard.check_required_files(fake_repo)
    assert findings == []


def test_required_files_flags_missing_file(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "policy.py").unlink()
    findings = ci_guard.check_required_files(fake_repo)
    assert len(findings) == 1
    assert findings[0].rule == "required_files"
    assert findings[0].path.as_posix() == "osint_core/policy.py"


# ---------- yaml_integrity ----------


def test_yaml_integrity_accepts_mapping(fake_repo: Path) -> None:
    findings = ci_guard.check_yaml_integrity(fake_repo)
    assert findings == []


def test_yaml_integrity_rejects_scalar(fake_repo: Path) -> None:
    (fake_repo / "data" / "sources.yaml").write_text("just-a-string\n")
    findings = ci_guard.check_yaml_integrity(fake_repo)
    assert len(findings) == 1
    assert findings[0].rule == "yaml_integrity"


def test_yaml_integrity_rejects_empty(fake_repo: Path) -> None:
    (fake_repo / "data" / "sources.yaml").write_text("")
    findings = ci_guard.check_yaml_integrity(fake_repo)
    assert any("empty" in f.message.lower() for f in findings)


def test_yaml_integrity_rejects_invalid_yaml(fake_repo: Path) -> None:
    (fake_repo / "data" / "sources.yaml").write_text("key: : :\n  - broken\n")
    findings = ci_guard.check_yaml_integrity(fake_repo)
    assert findings
    assert findings[0].rule == "yaml_integrity"


# ---------- forbidden_tools ----------


def test_forbidden_tools_passes_on_clean_repo(fake_repo: Path) -> None:
    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert findings == []


def test_forbidden_tools_flags_unallowlisted_reference(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "scanner.py").write_text(
        'CMD = "nmap -sV target"\n',
    )
    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert any(
        f.rule == "forbidden_tools"
        and f.path.as_posix() == "osint_core/scanner.py"
        for f in findings
    )


def test_forbidden_tools_allows_policy_file(fake_repo: Path) -> None:
    # policy.py is on the allowlist because ALIASES legitimately maps these
    # tool names to canonical forbidden modules.
    (fake_repo / "osint_core" / "policy.py").write_text(
        'ALIASES = {"nmap": "port_scan", "masscan": "port_scan"}\n',
    )
    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert findings == []


def test_forbidden_tools_word_boundary_avoids_false_positive(
    fake_repo: Path,
) -> None:
    # "metasploitable" contains the substring "metasploit" but is not a tool
    # invocation; the regex must require word boundaries.
    (fake_repo / "osint_core" / "notes.py").write_text(
        '# the metasploitable_lab fixture is unrelated\n',
    )
    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert findings == []


# ---------- raw_indicator_leakage ----------


def test_raw_indicator_leakage_clean(fake_repo: Path) -> None:
    findings = ci_guard.check_raw_indicator_leakage(fake_repo)
    assert findings == []


def test_raw_indicator_leakage_flags_example_domain(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "demo.py").write_text(
        'TARGET = "example.com"\n',
    )
    findings = ci_guard.check_raw_indicator_leakage(fake_repo)
    assert any(f.rule == "raw_indicator_leakage" for f in findings)


def test_raw_indicator_leakage_ignores_non_osint_core(fake_repo: Path) -> None:
    # Files outside osint_core/ are out of scope for this rule.
    (fake_repo / "tests").mkdir()
    (fake_repo / "tests" / "fixtures.py").write_text('TARGET = "example.com"\n')
    findings = ci_guard.check_raw_indicator_leakage(fake_repo)
    assert findings == []


def test_raw_indicator_leakage_allowlisted_validators(fake_repo: Path) -> None:
    # validators.py declares the 192.168.0.0/16 deny range.
    (fake_repo / "osint_core" / "validators.py").write_text(
        'PRIVATE = "192.168.0.0/16"\n',
    )
    findings = ci_guard.check_raw_indicator_leakage(fake_repo)
    assert findings == []


# ---------- passive_first ----------


def test_passive_first_clean(fake_repo: Path) -> None:
    findings = ci_guard.check_passive_first(fake_repo)
    assert findings == []


def test_passive_first_flags_unauthorized_get(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "fetcher.py").write_text(
        dedent(
            """
            import requests

            def lookup():
                return requests.get("https://example.test")
            """
        ).lstrip(),
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert any(
        f.rule == "passive_first"
        and f.path.as_posix() == "osint_core/fetcher.py"
        for f in findings
    )


def test_passive_first_accepts_authorized_context(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "fetcher.py").write_text(
        dedent(
            """
            import requests

            def lookup(authorized_target: bool):
                if not authorized_target:
                    raise PermissionError
                return requests.get("https://example.test")
            """
        ).lstrip(),
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert findings == []


def test_passive_first_ignores_non_requests_calls(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "client.py").write_text(
        dedent(
            """
            class Session:
                def get(self, url): ...

            session = Session()
            session.get("https://example.test")
            """
        ).lstrip(),
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert findings == []


def test_passive_first_skips_pseudocode_allowlist(fake_repo: Path) -> None:
    # drift.py is documented pseudocode; the rule must not blow up on it.
    (fake_repo / "osint_core" / "drift.py").write_text(
        "DEFINE foo AS bar\nFUNCTION baz()\n",
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert findings == []


def test_passive_first_reports_real_syntax_error(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "broken.py").write_text("def oops(:\n")
    findings = ci_guard.check_passive_first(fake_repo)
    assert any(
        f.rule == "passive_first" and "syntax error" in f.message.lower()
        for f in findings
    )


# ---------- CLI ----------


def test_main_returns_zero_on_clean_repo(fake_repo: Path, capsys) -> None:
    exit_code = ci_guard.main(["--root", str(fake_repo)])
    assert exit_code == 0
    assert "passed" in capsys.readouterr().out.lower()


def test_main_returns_one_on_violation(fake_repo: Path, capsys) -> None:
    (fake_repo / "osint_core" / "policy.py").unlink()
    exit_code = ci_guard.main(["--root", str(fake_repo)])
    assert exit_code == 1
    assert "failed" in capsys.readouterr().out.lower()


def test_main_list_lists_all_rules(capsys) -> None:
    exit_code = ci_guard.main(["--list"])
    assert exit_code == 0
    out = capsys.readouterr().out
    for name in (
        "required_files",
        "yaml_integrity",
        "forbidden_tools",
        "raw_indicator_leakage",
        "passive_first",
    ):
        assert name in out


def test_main_json_output_is_valid(fake_repo: Path, capsys) -> None:
    import json as _json

    ci_guard.main(["--root", str(fake_repo), "--json"])
    payload = _json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["findings"] == []


def test_main_rule_filter(fake_repo: Path, capsys) -> None:
    # Introduce a forbidden_tools violation; restrict to required_files only.
    (fake_repo / "osint_core" / "scanner.py").write_text('CMD = "nmap"\n')
    exit_code = ci_guard.main(
        ["--root", str(fake_repo), "--rule", "required_files"],
    )
    assert exit_code == 0
