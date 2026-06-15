## Description

<!-- Briefly describe what this PR does and which issue it addresses. -->

## QWED Enforcement Checklist

- [ ] No fallback execution added
- [ ] No new raw `eval` / `exec` usage introduced
- [ ] Verification is enforced before execution
- [ ] No silent error handling or bypass-oriented retries added
- [ ] No trust placed in model-provided expected values, reasoning, or confidence
- [ ] Failure paths remain fail-closed
- [ ] All parser boundaries use approved paths only (`safe_parse_expr`)
- [ ] If this touches an existing issue, verify it does not bypass any security boundary introduced since the issue was created

## Related Issues

<!-- Link related issues using `Closes #N`, `Fixes #N`, or `Relates to #N` -->
