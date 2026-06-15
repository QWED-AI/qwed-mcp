# Contributing to QWED-MCP

## Philosophy

QWED-MCP is part of the QWED deterministic verification ecosystem. Every
contribution must align with the principles in [QWED_RULES.md](QWED_RULES.md).

## Before You Start

1. Read [QWED_RULES.md](QWED_RULES.md) — these rules are non-negotiable.
2. Check existing issues for related work.
3. If you're adding a security boundary, ensure it has tests, regression tests,
   and CI enforcement.

## Pull Request Process

1. Create a feature branch from `main`.
2. Make your changes.
3. Ensure all existing tests pass.
4. Add tests for new functionality.
5. Update documentation if needed.
6. Open a PR using the pull request template.
7. Ensure the QWED Enforcement Checklist is satisfied.

## Security Boundaries

Every security boundary must be:

- **Explicit**: Clearly defined in code and documentation
- **Tested**: Unit tests + regression tests for known bypass patterns
- **Enforced**: CI gates that block violations
- **Fail-closed**: Unverifiable = blocked

## Approved Paths

| Operation | Allowed | Forbidden |
|---|---|---|
| Expression parsing | `safe_parse_expr()` | `parse_expr()`, `eval()`, `exec()` |
| Code execution | `RiskBasedExecutionGateway` | Raw `subprocess`, `os.system` |
| File access | Path-verified I/O | Unrestricted `open()` |

## Reporting Security Issues

Please report security vulnerabilities privately via GitHub Security
Advisories. Do not file public issues for confirmed vulnerabilities.
