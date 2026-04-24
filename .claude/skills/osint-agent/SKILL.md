---
name: osint-agent
description: Domain knowledge for the Claude-powered OSINT expert agent in agent/
---

# OSINT Agent Module

The `agent/` module provides a `claude-3-5-sonnet-20241022` powered OSINT expert (`OSINTAgent`).
Requires `ANTHROPIC_API_KEY` env var.

## Key design decisions

- **Prompt caching:** `OSINT_SYSTEM_PROMPT` (~2000 tokens) has `cache_control: {"type": "ephemeral"}`. One cached block is optimal — do not split the system prompt.
- **Extended thinking:** Always `thinking={"type": "enabled", "budget_tokens": 4000}`. `max_tokens` must exceed `budget_tokens`.
- **History format:** Store `response.content` (the full block list, not just `.text`) in conversation history to preserve thinking blocks across turns.
- **Streaming:** `stream_chat()` calls `stream.get_final_message()` after exhausting `stream.text_stream` to capture complete content blocks for history.

## Analysis types

`analyze_target(target, analysis_type)` dispatches to `build_analysis_prompt()`:
`full | passive | threat | footprint | breach | darkweb | socmint`

## Extending the agent

| Task | Where |
|---|---|
| Add analysis type | `build_analysis_prompt()` prompts dict + CLI `--type` choices |
| Modify persona/knowledge | `OSINT_SYSTEM_PROMPT` — cache invalidates automatically |
| New convenience method | Build prompt string, call `self.chat()`, follow `generate_ioc_report()` pattern |
