# Skill: Skill Creator

## Purpose

Use this skill to create or update Claude skill and agent definitions under `.claude/`.

The goal is to make future Claude work more consistent without creating vague, overlapping, or unsafe instructions.

## Scope

This skill may create or update:

- `.claude/skills/*.md`
- `.claude/agents/*.md`

It should not modify runtime application code unless the user explicitly asks for implementation changes.

## Skill creation rules

A good skill definition should include:

1. Purpose
   - When to use the skill.
   - What problem it solves.

2. Relevant files
   - The repo paths the skill usually touches.

3. Operating model
   - The sequence of reasoning or actions the skill should follow.

4. Hard invariants
   - Things the skill must not violate.

5. Preferred checks
   - Targeted tests, lint, format, or review checks.

6. Expected output
   - The shape of the response or patch summary.

## Agent creation rules

A good agent definition should include:

1. Role
   - The specialist perspective the agent provides.

2. Use cases
   - When the orchestrator should route work to it.

3. Review priorities
   - What it should inspect first.

4. Red flags
   - Patterns that require correction or escalation.

5. Expected output
   - How findings or recommendations should be reported.

## Naming conventions

Use lowercase kebab-case filenames:

```text
.claude/skills/constraint-aware-invention-engine.md
.claude/skills/skill-creator.md
.claude/agents/orchestrator-agent.md
.claude/agents/constraint-safety-reviewer.md
```

Names should be specific enough to avoid overlap. Do not create broad names like `helper.md`, `general.md`, or `reviewer.md`.

## Repository safety rules

All skills and agents in this repository must preserve these guarantees:

- Passive by default.
- No scanning, brute forcing, credential testing, exploitation, or unscoped target interaction.
- Policy remains the source of truth for authorization and target-touch metadata.
- No raw indicators in audit, ledger, reports, or logs.
- No automated policy mutation.
- No new correction verbs without explicit approval.

## Update workflow

When adding or changing a skill/agent:

1. Check whether an existing definition already covers the use case.
2. Prefer updating an existing definition over creating a duplicate.
3. Add the smallest useful instruction set.
4. Keep instructions concrete and testable.
5. Reference repository paths, not vague abstractions.
6. Summarize the intended routing behavior.

## Expected output

Return:

- files added or changed
- why each definition exists
- which agent or skill should use it
- any overlap with existing definitions
- whether runtime code was untouched
