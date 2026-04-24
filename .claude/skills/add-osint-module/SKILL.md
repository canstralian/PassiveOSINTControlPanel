---
name: add-osint-module
description: Add a new passive OSINT enrichment module to the control panel
disable-model-invocation: true
---

Add a new OSINT enrichment module: $ARGUMENTS

Follow this sequence:

1. **Define in `osint_core/policy.py`:**
   - Add entry to `MODULE_POLICIES` with `risk`, `authorized_only`, `passive_only`, `description`
   - Add alias(es) to `ALIASES` if applicable
   - `risk` must be one of: `"passive"`, `"low"`, `"medium"`, `"high"`, `"forbidden"`
   - Add a test in `tests/test_policy.py` covering the new module's auth rules

2. **Mirror into `app.py`:**
   - Add to `PASSIVE_MODULES` (if passive) or `AUTHORIZED_ONLY_MODULES` (if auth-required)
   - Add to `OSINT_LINKS` if there is a reference URL
   - Implement enrichment logic in `run_enrichment()` under the module's canonical snake_case key

3. **Register in `data/sources.yaml`:** name, url, type, tags

4. **Wire into `osint_core/orchestrator.py` (for programmatic access):**
   - Define a `Tool` with type, description, auth requirements, timeout
   - Create a `Skill` referencing the tool and valid indicator types
   - Add to `SKILLS_REGISTRY`
   - Implement in `_execute_skill()`
   - Add test in `tests/test_orchestrator.py`

5. **Verify:**
   ```bash
   pytest tests/test_policy.py tests/test_orchestrator.py -v
   ruff check .
   python app.py  # exercise the module manually
   ```

**Invariants:**
- Never set `authorized_only=False` for modules that make outbound requests to the target.
- Never log the raw indicator — use the HMAC hash.
- Route all UI input through `canonicalize_module_name` before policy checks.
