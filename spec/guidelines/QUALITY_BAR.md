---
description: Quality expectations — when to spec, testing, anti-patterns, AI workflow
alwaysApply: true
---

# <Project> — Quality Bar

## When to Create a Feature Spec

Create a spec if the work:

- <Condition — e.g. touches async/lifecycle code>
- <Condition — e.g. modifies security-sensitive flows>
- <Condition — e.g. changes core behavior>
- Could regress existing behavior

**Skip the spec** if:

- Pure cosmetic changes
- Bug fix with obvious cause and fix
- Dependency update with no API changes

When in doubt, create a spec. The overhead is low.

## Testing

- <What must be tested>
- <What test patterns to follow>
- <What must NOT happen in tests — e.g. no real network calls>

## Implementation Expectations

- Follow existing patterns in the nearest module.
- Avoid introducing new architectural layers unless required by a spec.
- Prefer extending existing abstractions over introducing new ones.
- Code must be structured for human review first, not for AI generation convenience.

## Anti-Patterns

- Silent failures
- <Stack-specific anti-patterns>

## Working With AI

- Spec-first for behavior changes.
- Work packets in `spec/work/` for non-trivial tasks.
- If a spec is unclear or incorrect, stop and report a Spec Issue — do not guess.
- Never modify `spec/guidelines/` without explicit permission.

## Knowledge Entries

After a work packet merges, promote non-obvious decisions to `spec/knowledge/DEC-XXX-*.md`. See `spec/knowledge/_TEMPLATE.md` for format and criteria.

### Task Completeness

For non-trivial work, changes are not complete unless:

- Work packet reflects the actual work performed
- No significant code exists outside the task plan
- Edge cases and failure modes are addressed
