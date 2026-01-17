# QWED-MCP Examples

This folder contains example scripts and sample prompts for using QWED-MCP.

## Sample Prompts for Claude Desktop

Copy and paste these prompts into Claude Desktop to test QWED-MCP:

### 1. Basic Math Verification
```
Verify the derivative of x³ equals 3x² using verify_math
```

### 2. Financial Calculation - Compound Interest
```
A bank advertises: "Invest $10,000 at 7.5% annual rate compounded quarterly for 5 years and you'll have $14,356.29"

Use verify_math to check if this is correct. 
Formula: A = P(1 + r/n)^(nt) where P=10000, r=0.075, n=4, t=5
```

### 3. Loan EMI Calculation
```
A car dealer claims: "₹10,00,000 loan at 9% annual interest for 5 years = EMI of ₹20,758"

Verify using verify_math with EMI formula:
EMI = P × r × (1+r)^n / ((1+r)^n - 1)
where P=1000000, r=0.09/12, n=60
```

### 4. Logic Verification - Syllogism
```
Use verify_logic to check this argument:
Premises:
1. All mammals are warm-blooded
2. Dolphins are mammals

Conclusion: Dolphins are warm-blooded
```

### 5. Business Logic Validation
```
Use verify_logic to validate this tax rule:
Premises:
1. If income > 1000000 then tax_bracket is 30%
2. If income <= 1000000 AND income > 500000 then tax_bracket is 20%
3. My income is 750000

Conclusion: My tax_bracket is 20%
```

### 6. Code Security - Dangerous Functions
```
Use verify_code to check this Python code for security issues:

def run_command(user_input):
    os.system(user_input)
    result = eval(get_response())
    return result
```

### 7. Code Security - Trading Algorithm
```
Use verify_code to check this trading function:

def execute_trade(order_data):
    command = f"python executor.py --order '{order_data}'"
    os.system(command)
    return eval(get_response())
```

### 8. SQL Injection Detection
```
Use verify_sql to check this query for security issues:
SELECT * FROM users WHERE id = '1' OR '1'='1'
```

### 9. SQL Injection - Payment System
```
A developer wrote this payment query. Use verify_sql to check:

SELECT account_balance, credit_limit 
FROM customer_accounts 
WHERE customer_id = '12345' OR '1'='1' 
AND account_type = 'premium'
```

### 10. Safe SQL Validation
```
Use verify_sql to check if this parameterized query is safe:
SELECT name, email FROM users WHERE id = ?
```

---

## Python Client Example

See `python_client.py` for programmatic usage of QWED-MCP.

## Integration Examples

See `langchain_integration.py` for using QWED-MCP with LangChain agents.
