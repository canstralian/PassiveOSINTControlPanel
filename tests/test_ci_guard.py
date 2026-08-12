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


def test_forbidden_tools_allows_passive_scope_rules_yaml(fake_repo: Path) -> None:
    # policy/passive_scope_rules.yaml is now on the allowlist because it
    # declares nmap/masscan in the forbidden deny list.
    (fake_repo / "policy").mkdir()
    (fake_repo / "policy" / "passive_scope_rules.yaml").write_text(
        "forbidden:\n  - nmap\n  - masscan\n",
    )
    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert findings == []


def test_forbidden_tools_allows_expanded_test_allowlist_entries(
    fake_repo: Path,
) -> None:
    # Each of these test files was newly added to the allowlist because they
    # feed a forbidden tool name in as *input* to assert the passive-first
    # gate rejects or remaps it.
    (fake_repo / "tests").mkdir()
    for name in (
        "test_adaptation.py",
        "test_audit.py",
        "test_constraint_ledger.py",
        "test_constraints.py",
        "test_enrichment.py",
        "test_invention_loop.py",
        "test_passive_boundaries.py",
    ):
        (fake_repo / "tests" / name).write_text('BLOCKED_MODULE = "nmap"\n')

    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert findings == []


def test_forbidden_tools_new_test_file_not_on_allowlist_is_still_flagged(
    fake_repo: Path,
) -> None:
    # The allowlist is an explicit per-file enumeration on purpose: a test
    # file that is NOT enumerated must still be caught by the rule.
    (fake_repo / "tests").mkdir()
    (fake_repo / "tests" / "test_something_new.py").write_text(
        'BLOCKED_MODULE = "nmap"\n',
    )
    findings = ci_guard.check_forbidden_tools(fake_repo)
    assert any(
        f.rule == "forbidden_tools" and f.path.as_posix() == "tests/test_something_new.py"
        for f in findings
    )


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


def test_passive_first_skips_pseudocode_allowlist(
    fake_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file on the pseudocode allowlist is exempt from the syntax-error
    # sub-check. drift.py is now real Python and the default allowlist is empty,
    # so exercise the mechanism with a synthetic allowlisted file.
    (fake_repo / "osint_core" / "legacy_spec.py").write_text(
        "DEFINE foo AS bar\nFUNCTION baz()\n",
    )
    monkeypatch.setattr(
        ci_guard,
        "PASSIVE_FIRST_PSEUDOCODE_ALLOWLIST",
        ("osint_core/legacy_spec.py",),
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert findings == []


def test_passive_first_reports_syntax_error_when_not_allowlisted(
    fake_repo: Path,
) -> None:
    # With the default (empty) allowlist, pseudocode in osint_core/ must be
    # reported rather than silently skipped.
    (fake_repo / "osint_core" / "legacy_spec.py").write_text(
        "DEFINE foo AS bar\nFUNCTION baz()\n",
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert any(
        f.rule == "passive_first"
        and f.path.as_posix() == "osint_core/legacy_spec.py"
        for f in findings
    )


def test_passive_first_pseudocode_allowlist_defaults_to_empty() -> None:
    # osint_core/drift.py is now real Python and must parse; the default
    # allowlist must no longer carve out any exemption.
    assert ci_guard.PASSIVE_FIRST_PSEUDOCODE_ALLOWLIST == ()


def test_passive_first_pseudocode_allowlist_supports_directory_prefix(
    fake_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # check_passive_first now uses path_in() (prefix-aware) rather than an
    # exact-match membership test, so a directory-style allowlist entry
    # (trailing "/") must exempt every file underneath it.
    (fake_repo / "osint_core" / "legacy").mkdir()
    (fake_repo / "osint_core" / "legacy" / "spec_a.py").write_text(
        "DEFINE foo AS bar\n",
    )
    (fake_repo / "osint_core" / "legacy" / "spec_b.py").write_text(
        "FUNCTION baz(\n",
    )
    monkeypatch.setattr(
        ci_guard,
        "PASSIVE_FIRST_PSEUDOCODE_ALLOWLIST",
        ("osint_core/legacy/",),
    )
    findings = ci_guard.check_passive_first(fake_repo)
    assert findings == []


def test_passive_first_real_drift_module_parses_without_syntax_error() -> None:
    # Regression guard for the exact change in this PR: osint_core/drift.py
    # was rewritten from pseudocode to real Python and removed from the
    # allowlist. It must parse cleanly and must not appear in the findings
    # for the passive_first rule against the actual repository.
    findings = ci_guard.check_passive_first(ci_guard.REPO_ROOT)
    assert not any(f.path.as_posix() == "osint_core/drift.py" for f in findings)


def test_passive_first_reports_real_syntax_error(fake_repo: Path) -> None:
    (fake_repo / "osint_core" / "broken.py").write_text("def oops(:\n")
    findings = ci_guard.check_passive_first(fake_repo)
    assert any(
        f.rule == "passive_first" and "syntax error" in f.message.lower()
        for f in findings
    )


# ---------- traversal fallback ----------


def test_walk_fallback_prunes_excluded_dirs(tmp_path: Path) -> None:
    """When git is unavailable, _walk_with_pruning must skip .git/, .venv/,
    and __pycache__ wholesale instead of walking into them.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("x = 1\n")

    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "site.py").write_text("# huge tree\n")
    (tmp_path / "src" / "__pycache__").mkdir()
    (tmp_path / "src" / "__pycache__" / "keep.cpython-312.pyc").write_text("x")

    walked = sorted(p.as_posix() for p in ci_guard._walk_with_pruning(tmp_path))
    assert walked == ["src/keep.py"]


def test_should_skip_dir_excludes_dotgit_and_pycache() -> None:
    assert ci_guard.should_skip_dir(Path(".git"))
    assert ci_guard.should_skip_dir(Path(".venv"))
    assert ci_guard.should_skip_dir(Path("src/__pycache__"))
    assert not ci_guard.should_skip_dir(Path("src"))
    # File-shaped prefixes (README.md) must not prune directories.
    assert not ci_guard.should_skip_dir(Path("README.md"))


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
