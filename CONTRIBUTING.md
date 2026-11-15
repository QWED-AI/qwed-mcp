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

## Licence

QWED-MCP is licensed under the [Apache License 2.0](./LICENSE), and contributions are accepted under the same licence:

- **Inbound = outbound.** Under section 5 of the licence, a contribution you submit for inclusion is licensed under the Apache License 2.0, with no additional terms, unless you explicitly state otherwise.
- **You keep your copyright.** The licence lets everyone, the maintainer included, use, change and redistribute your contribution. Under section 3 you also grant a patent licence, limited to the patent claims you can license that your contribution necessarily infringes, alone or combined with QWED-MCP.
- **Only submit what you have the right to submit:** your own work, or code under a licence that is compatible with Apache-2.0, with its notices kept. Code under the GPL, the AGPL or another licence that is not compatible cannot be accepted.
- **The names are not licensed.** See [TRADEMARKS.md](./TRADEMARKS.md) for using "QWED" and its logo, and [NOTICE](./NOTICE) for the attribution that redistributions keep.
