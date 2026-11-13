# QWED-MCP Examples

QWED-MCP registers two tools:

- `execute_python_code` runs Python code after the allowlist admission check (see [What code is admitted](../README.md#what-code-is-admitted));
- `verification_status` reads the result of a job started with `"background": true`.

Code execution is off by default. The server's environment must set `QWED_MCP_TRUSTED_CODE_EXECUTION=true`, and admitted code then runs with the server's privileges.

The `verify_math`, `verify_logic`, `verify_code` and `verify_sql` tools were removed in v0.2.1. If Claude tries to call one, tell it to write and run a script with `execute_python_code` instead.

## Sample prompts for Claude Desktop

### 1. Compound interest

```
A bank advertises: "Invest $10,000 at 7.5% annual rate compounded quarterly for 5 years and you'll have $14,356.29".

Write a Python script that computes this with the decimal module, A = P(1 + r/n)^(nt) with P=10000, r=0.075, n=4, t=5, rounds to cents and compares it with the claim. Run it with execute_python_code.
```

The script prints 14499.48, so the claim is wrong: 14,356.29 is what annual compounding gives.

### 2. Loan EMI

```
A car dealer claims: "₹10,00,000 loan at 9% annual interest for 5 years = EMI of ₹20,758".

Write a Python script with the decimal module for EMI = P × r × (1+r)^n / ((1+r)^n - 1), with P=1000000, r=0.09/12, n=60, and run it with execute_python_code.
```

The script prints 20758.36, so the claim holds to the rupee.

### 3. A syllogism

```
Premises: all mammals are warm-blooded; dolphins are mammals.
Conclusion: dolphins are warm-blooded.

Write a Python script that checks the argument over every true/false assignment with itertools.product, and run it with execute_python_code.
```

### 4. A business rule

```
Rules: income above 1,000,000 is taxed at 30%; income above 500,000 and up to 1,000,000 at 20%.
My income is 750,000. Write a Python script that applies the rules and prints my bracket, and run it with execute_python_code.
```

### 5. Code that is refused

```
Run this with execute_python_code:

import os
print(os.listdir("."))
```

The server refuses it before it runs and gives the reason: `Module 'os' is not admitted`. Code that imports a module outside the allowlist, calls a refused builtin such as `open`, `eval` or `getattr`, or reads a private attribute is refused the same way.

### 6. A long job in the background

```
Run a script with execute_python_code and "background": true that sums 1/k² for k from 1 to 2,000,000 and compares it with π²/6, then read the result with verification_status.
```

## Python client

`python_client.py` starts the server over stdio and calls both tools: two admitted scripts, one refused script, and a background job read back with `verification_status`.

```bash
pip install qwed-mcp
python examples/python_client.py
```

## SQL, logic and math checks as a library

The math, logic and SQL engines are not MCP tools. Python code can call them directly, for example:

```python
from qwed_mcp.engines.sql_engine import verify_sql_query

verify_sql_query("SELECT * FROM users WHERE id = '1' OR '1'='1'")
# {'verified': False, ...}: the condition does not depend on the row
```
