# Copilot Instructions for QWED-MCP

Read and follow [QWED_RULES.md](../QWED_RULES.md) for every suggestion.

Additional repository-specific rules:

- Do not suggest fallback execution paths.
- Do not suggest graceful degradation that continues past failed verification.
- Do not suggest retries that weaken enforcement.
- Do not trust model output as proof of correctness.
- Do not suggest trust scoring, heuristics, or probabilistic approval.
- Prefer fail-closed behavior over convenience or availability.
- All parser boundaries must use approved paths only (safe_parse_expr, never bare parse_expr/eval/exec).
- If a suggestion conflicts with QWED enforcement rules, the suggestion must be rejected.
