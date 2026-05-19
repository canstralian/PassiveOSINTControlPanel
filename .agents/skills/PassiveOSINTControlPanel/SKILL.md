```markdown
# PassiveOSINTControlPanel Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you how to contribute to the PassiveOSINTControlPanel Python project, focusing on its coding conventions, module structure, and common development workflows. You'll learn how to implement new features with tests, refactor core modules, and follow the project's style for code organization and testing.

## Coding Conventions

- **Language:** Python
- **Framework:** None detected
- **File Naming:** Use `snake_case` for all file and module names.
  - Example: `constraints.py`, `test_constraints.py`
- **Import Style:** Use relative imports within packages.
  - Example:
    ```python
    from .constraints import Constraint
    ```
- **Export Style:** Use named exports in `__init__.py` to expose module functionality.
  - Example (`osint_core/__init__.py`):
    ```python
    from .constraints import Constraint
    __all__ = ["Constraint"]
    ```
- **Commit Messages:** Freeform, no strict prefix, average length ~53 characters.

## Workflows

### Feature Implementation with Tests
**Trigger:** When adding a new core functionality or module and ensuring it is properly tested.  
**Command:** `/new-feature-with-tests`

1. Implement new logic or module in `osint_core` (e.g., `constraints.py`).
    ```python
    # osint_core/constraints.py
    class Constraint:
        def __init__(self, rule):
            self.rule = rule
        def is_satisfied(self, data):
            # logic here
            return True
    ```
2. Update or create `__init__.py` to expose new functionality if needed.
    ```python
    # osint_core/__init__.py
    from .constraints import Constraint
    __all__ = ["Constraint"]
    ```
3. Write or update tests in `tests/` (e.g., `test_constraints.py`) to cover new behaviors and pin invariants.
    ```python
    # tests/test_constraints.py
    from osint_core import Constraint

    def test_constraint_satisfied():
        c = Constraint(rule="example")
        assert c.is_satisfied("example data")
    ```

### Refactor or Tighten Core Module and Tests
**Trigger:** When improving, refactoring, or clarifying the logic or API of an existing core module and ensuring tests reflect the changes.  
**Command:** `/refactor-core-module`

1. Refactor or update logic in the core module (e.g., `constraints.py`).
    ```python
    # osint_core/constraints.py
    class Constraint:
        def __init__(self, rule, strict=False):
            self.rule = rule
            self.strict = strict
        # updated logic...
    ```
2. Update or add tests in `tests/` (e.g., `test_constraints.py`) to pin new behaviors or invariants.
    ```python
    # tests/test_constraints.py
    def test_constraint_strict_mode():
        c = Constraint(rule="example", strict=True)
        assert not c.is_satisfied("other data")
    ```

## Testing Patterns

- **Framework:** Unknown (use standard `pytest` or `unittest` conventions)
- **Test File Pattern:** All test files are named with the pattern `test_*.py` and placed in the `tests/` directory.
- **Test Example:**
    ```python
    # tests/test_constraints.py
    from osint_core import Constraint

    def test_constraint_behavior():
        c = Constraint(rule="data")
        assert c.is_satisfied("data")
    ```

## Commands
| Command                   | Purpose                                                        |
|---------------------------|----------------------------------------------------------------|
| /new-feature-with-tests   | Scaffold a new feature/module with corresponding tests         |
| /refactor-core-module     | Refactor or clarify a core module and update related tests     |
```