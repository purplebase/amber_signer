---
description: Non-negotiable invariants — <brief summary of key areas>
alwaysApply: true
---

# <Project> — Invariants

These are non-negotiable. Violating any invariant is a bug — no tradeoffs or exceptions.

## <Category 1>

- <Rule>
- <Rule>

## <Category 2>

- <Rule>
- <Rule>

## Error Handling

- All errors must be wrapped with context.
- Errors must propagate up; never swallowed silently.
- User-facing error messages must be actionable.
