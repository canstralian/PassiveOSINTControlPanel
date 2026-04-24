# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Passive OSINT Control Panel — a Gradio-based Hugging Face Space for drift-aware,
passive-first OSINT enrichment. Inputs are validated, sanitised, normalised, and
HMAC-hashed before any logging or enrichment. External-target interaction is
gated behind explicit authorization.

- **Entry point:** `app.py` (Gradio `demo.launch()`)
- **Runtime:** Python 3.11+, Gradio 6.13.x, HF Space SDK `gradio`
- **Version:** `0.1.0` (`APP_VERSION` in `app.py`, `__version__` in `osint_core/__init__.py`)
- **License:** Apache-2.0
- **HF Space front matter** lives at the top of `README.md` — do not strip it.

## Repository layout

```
.
├── app.py                    # Monolithic Gradio UI + full pipeline (current prod)
├── osint_core/               # Modular refactor of app.py's logic (preferred for new code)
│   ├── __init__.py           # Public API: validate_indicator, create_orchestrator, ...
│   ├── validators.py         # Input validation + normalisation (pure, no I/O)
│   ├── policy.py             # Module authorization boundary + correction verb gate
│   ├── orchestrator.py       # Agent-based workflow coordination
│   └── drift.py              # DRIFT LAYER — currently PSEUDOCODE, not runnable (see below)
├── agent/                    # Claude-powered OSINT expert agent (NEW)
│   ├── __init__.py           # Exports OSINTAgent
│   ├── osint_agent.py        # OSINTAgent class — claude-3-5-sonnet-20241022, extended thinking, prompt caching
│   └── cli.py                # argparse CLI: --target, --type, --iocs, --explain, interactive mode
├── tests/
│   ├── test_policy.py        # Passes against osint_core.policy
│   ├── test_orchestrator.py  # Passes against osint_core.orchestrator
│   └── test_drift.py         # Contract tests — FAIL until drift.py is implemented
├── data/sources.yaml         # OSINT source registry (subset; app.py has its own inline copy)
├── policy.yaml               # Declarative policy snapshot (mirrors osint_core.policy)
├── manifest.json             # Artifact manifest skeleton
├── golden_tests.json         # Smoke-test fixtures for classification
├── requirements.txt          # Python deps (pinned ranges)
├── packages.txt              # HF Space apt packages (dnsutils, whois, libmagic1)
└── README.md                 # User/operator docs + HF Space config
```

Two layers coexist:
- `app.py` is self-contained and ships the running Space today.
- `osint_core/` is the modular refactor targeted by the test suite. New logic
  should land in `osint_core/` and be wired into `app.py` rather than expanded
  in `app.py` directly.

## Orchestrator agent architecture

The `osint_core/orchestrator.py` module provides an agent-based workflow
coordination system. It separates concerns into:

- **Agent**: `OrchestratorAgent` coordinates the full enrichment workflow
- **Skills**: High-level capabilities (e.g., "Resolve DNS", "Fetch WHOIS")
- **Tools**: Atomic external actions (e.g., DNS query, HTTP request, subprocess)
- **Execution context**: Tracks state through validation → policy → enrichment → drift → audit

### Key data structures

- `Tool`: Atomic capability (subprocess, network, file, computation)
- `Skill`: Composed capability with required indicator types and tools
- `ExecutionContext`: Per-request state (run ID, normalized indicator, policy eval, errors)
- `SkillResult`: Result from executing a skill (status, data, error, duration)
- `EnrichmentWorkflow`: Complete workflow result with all execution details

### Workflow execution pattern

```python
from osint_core import create_orchestrator

agent = create_orchestrator()
workflow = agent.execute_workflow(
    raw_indicator="example.com",
    indicator_type_hint="Domain",
    requested_modules=["resource_links", "dns_records"],
    authorized_target=False,
    passive_only=True,
)

# workflow.validation_result → ValidationResult
# workflow.policy_evaluation → PolicyEvaluation
# workflow.skill_results → list[SkillResult]
# workflow.drift_vector → dict[str, float]
# workflow.correction_verb → "ADAPT" | "CONSTRAIN" | "REVERT" | "OBSERVE"
```

### Adding new skills

1. Define a `Tool` with type, description, auth requirements, timeout
2. Create a `Skill` that references the tool(s) and required indicator types
3. Register the skill in `SKILLS_REGISTRY` with a canonical name
4. Add skill execution logic in `OrchestratorAgent._execute_skill`
5. Add corresponding test in `tests/test_orchestrator.py`

Do not add skills directly to `app.py`; add them to `orchestrator.py` and wire
them through the orchestrator API.

## AI Agent (Claude-powered)

`agent/osint_agent.py` — `OSINTAgent` wraps `claude-3-5-sonnet-20241022` with extended thinking
and prompt caching (the ~2000-token system prompt is cached via `cache_control: ephemeral`,
cutting input costs ~90% after the first turn).

```python
from agent import OSINTAgent

agent = OSINTAgent()  # reads ANTHROPIC_API_KEY from env
result = agent.analyze_target("example.com", analysis_type="passive")  # or: full|threat|footprint|breach|darkweb|socmint
report = agent.generate_ioc_report(["1.2.3.4", "evil.com"])
```

CLI: `python -m agent.cli --target example.com --type passive`
or interactive: `python -m agent.cli`

Conversation history preserves full `response.content` blocks (including thinking blocks)
for correct multi-turn context propagation.

## Known state / critical gotchas

1. **`osint_core/drift.py` is pseudocode, not Python.** It uses `DEFINE`,
   `FUNCTION`, `RETURN`, `FOR … IN` as bare keywords and will raise
   `SyntaxError` on import. `tests/test_drift.py` imports
   `DriftAssessment`, `DriftSignal`, `DriftType`, `DriftVector`,
   `TelemetrySnapshot`, `aggregate_signals`, `assess_drift`,
   `choose_dominant_drift_type`, `estimate_confidence`, and
   `recommend_correction` — these are not yet implemented in Python. Treat
   `drift.py` as a spec to implement against the tests, not as working code
   to edit in-place.
2. **Two module registries.** `app.py` hard-codes `OSINT_LINKS`,
   `PASSIVE_MODULES`, `AUTHORIZED_ONLY_MODULES`. `osint_core/policy.py` has
   the canonical `MODULE_POLICIES` registry plus `ALIASES`. When adding a
   module, update the `osint_core` registry first; mirror into `app.py` only
   if the UI needs it.
3. **Two validators.** `app.py` has inline `sanitize_text` /
   `classify_and_normalize` / `validate_as_type`. `osint_core/validators.py`
   is the stricter, structured replacement (`ValidationResult`,
   `ValidationErrorCode`). Prefer `osint_core` for new code paths.
4. **`OSINT_HASH_SALT` is required.** `app.py:get_hash_salt` raises on
   startup without it. For local/dev only, set `ALLOW_DEV_SALT=true`. Never
   commit a salt value.
5. **Correction verbs are a closed set:** `ADAPT`, `CONSTRAIN`, `REVERT`,
   `OBSERVE`. Do not introduce new verbs; `policy.enforce_correction_verb`
   rejects anything else.
6. **`policy.yaml` says `immutable: true`.** Policy changes require the
   out-of-band gate in `policy.enforce_policy_mutation_gate`. Do not silently
   broaden rules.

## Design invariants (must not be violated)

From `policy.yaml`, `manifest.json`, and `app.py:make_manifest`:

- Passive by default. No scanning, brute forcing, credential testing, or
  exploitation — these are `risk="forbidden"` in `MODULE_POLICIES` and must
  stay that way.
- Validation runs before anything else. Downstream code does not re-validate.
- Hash (HMAC-SHA256 with `OSINT_HASH_SALT`, lowercased input) before writing
  to audit logs. Raw indicators never enter audit payloads —
  `policy.enforce_audit_payload` rejects `raw_indicator`, `raw_input`,
  `indicator`, `email`, `domain`, `username`, `url`, `ip` keys.
- Authorized-only modules (`http_headers`, `robots_txt`, `screenshot`) stay
  blocked unless the caller asserts `authorized_target=True` AND
  `passive_only=False`.
- Drift detection is pure — it does not mutate telemetry, baseline, manifest,
  or policy input. See `test_assess_drift_is_pure_and_does_not_mutate_inputs`.
- Correction priority: **policy > structural > behavioral > adversarial >
  operational > statistical.** Adversarial CONSTRAINs before the system
  ADAPTs. Statistical drift may ADAPT only when nothing higher-priority fires.

## Development workflow

### Setup

```bash
pip install -r requirements.txt
# pytest and lint tooling are not in requirements.txt — install ad hoc:
pip install pytest ruff bandit pip-audit
export OSINT_HASH_SALT="$(python -c 'import secrets;print(secrets.token_hex(32))')"
# or for local-only:
export ALLOW_DEV_SALT=true
# for agent/ module:
export ANTHROPIC_API_KEY=<your-key>
```

### Run the app

```bash
python app.py
# Gradio binds to 127.0.0.1:7860 by default.
```

### Test

```bash
pytest                    # expect test_policy to pass; test_drift will fail
pytest tests/test_policy.py -v
pytest tests/test_policy.py::TestPolicyEnforcement::test_passive_only -v  # single test
```

Before claiming drift work is done, `pytest tests/test_drift.py` must pass.

### Lint / security scan (per README)

```bash
ruff check .
bandit -r osint_core/
pip-audit
```

None of these are wired into CI yet — run locally.

## Conventions

- **Python:** type hints throughout, `from __future__ import annotations`,
  `@dataclass(frozen=True)` for value objects, `Literal[...]` for closed
  enums. Match the existing style in `osint_core/validators.py` and
  `osint_core/policy.py`.
- **Errors:** structured exceptions with an error-code enum
  (`ValidationErrorCode`, `PolicyErrorCode`). Prefer returning a result
  dataclass (`ValidationResult`, `PolicyEvaluation`) over raising for
  expected failure paths; raise only at enforcement boundaries
  (`assert_valid_or_raise`, `enforce_*`).
- **Module naming:** UI labels are human (`"HTTP Headers"`); canonical names
  are snake_case (`"http_headers"`). Route every UI input through
  `canonicalize_module_name` before policy checks.
- **No new dependencies without reason.** `requirements.txt` uses pinned
  ranges; preserve the lower/upper bounds when bumping.
- **Never log raw indicators.** Add a test in the style of
  `test_audit_payload_blocks_raw_indicator_fields` when introducing new
  audit sinks.
- **Docstrings:** module-level docstrings state design intent (see
  `validators.py`, `policy.py`). Keep that pattern for new modules.

## Git workflow

- Default branch: `main`.
- Claude work branch (this environment): `claude/skills-agent-osint-4zbxP`.
  Push only to the designated feature branch; never force-push `main`.
- GitHub repo scope for MCP tools: `canstralian/passiveosintcontrolpanel`
  only. Other repos are denied.
- After pushing, open a **draft** PR if one does not already exist.
- Commit style from `git log`: short imperative titles
  (`Create osint_core/policy.py`, `Update requirements.txt`).

## Where to make common changes

| Task | File(s) |
| --- | --- |
| Add a new OSINT source link | `app.py:OSINT_LINKS` and `data/sources.yaml` |
| Add / change a module's risk or auth requirement | `osint_core/policy.py:MODULE_POLICIES` + test in `tests/test_policy.py` + mirror in `policy.yaml` |
| Tighten input validation | `osint_core/validators.py` (regexes, `DANGEROUS_PATTERNS`, `PRIVATE_NETS`) |
| Implement drift detection | `osint_core/drift.py` — rewrite the pseudocode to satisfy `tests/test_drift.py` |
| Change correction verbs | Forbidden without out-of-band approval; touches `osint_core/policy.py:ALLOWED_CORRECTION_VERBS`, `app.py:CorrectionVerb`, and `policy.yaml` |
| Wire a new module into the UI | `app.py:PASSIVE_MODULES`, `run_enrichment`, and the Gradio `CheckboxGroup` |
| Change audit schema | `app.py:TelemetryEvent` + `write_audit` + any consumer in `export_audit_index` |
| Add a new orchestrator skill | `osint_core/orchestrator.py:SKILLS_REGISTRY` + tool definition + test in `tests/test_orchestrator.py` |
| Extend the AI agent's analysis types | `agent/osint_agent.py:_build_analysis_prompt` (add to the `prompts` dict) |
| Adjust the AI agent's OSINT persona / knowledge | `agent/osint_agent.py:OSINT_SYSTEM_PROMPT` (re-cache will happen automatically on next call) |

## Runtime artifacts (gitignored-ish)

`app.py` creates `runs/reports/` and `runs/audit/` on import and writes per-run
`.md` and `.json` files there. These directories are not tracked; do not
commit their contents.
