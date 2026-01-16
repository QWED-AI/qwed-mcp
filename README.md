# QWED-MCP

[![PyPI](https://img.shields.io/pypi/v/qwed-mcp?color=blue&label=PyPI)](https://pypi.org/project/qwed-mcp/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green)](https://modelcontextprotocol.io)

**MCP Server for QWED Verification - Use QWED verification tools in Claude Desktop, VS Code, and any MCP client.**

---

## What is QWED-MCP?

QWED-MCP brings deterministic verification to any MCP-compatible AI assistant. Instead of trusting LLMs to compute correctly, QWED-MCP provides tools that verify outputs using:

- **SymPy** for mathematical verification
- **Z3 SMT Solver** for logical reasoning
- **AST Analysis** for code security
- **Pattern Matching** for SQL injection detection

---

## Installation

```bash
pip install qwed-mcp
```

Or install from source:

```bash
git clone https://github.com/QWED-AI/qwed-mcp.git
cd qwed-mcp
pip install -e .
```

---

## Quick Start

### Use with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qwed-verification": {
      "command": "qwed-mcp"
    }
  }
}
```

### Use with VS Code

Install the MCP extension and add to settings:

```json
{
  "mcp.servers": {
    "qwed-verification": {
      "command": "qwed-mcp"
    }
  }
}
```

---

## Available Tools

### `verify_math`

Verify mathematical calculations using SymPy.

```
Input: expression="x^2", claimed_result="2x", operation="derivative"
Output: ✅ VERIFIED - The derivative of x^2 is indeed 2x
```

### `verify_logic`

Verify logical arguments using Z3 SMT solver.

```
Input: premises=["All humans are mortal", "Socrates is human"], conclusion="Socrates is mortal"
Output: ✅ VERIFIED - The conclusion logically follows from the premises
```

### `verify_code`

Check code for security vulnerabilities.

```
Input: code="eval(user_input)", language="python"
Output: ❌ FAILED - Dangerous function call: eval()
```

### `verify_sql`

Detect SQL injection and validate queries.

```
Input: query="SELECT * FROM users WHERE id = '1' OR '1'='1'"
Output: ❌ FAILED - Potential SQL injection detected
```

---

## How It Works

```
┌─────────────────────────────────────────┐
│     Claude Desktop / VS Code            │
│          (MCP Client)                   │
└───────────────────┬─────────────────────┘
                    │ MCP Protocol
                    ▼
┌─────────────────────────────────────────┐
│          QWED-MCP Server                │
├─────────────────────────────────────────┤
│  Tools:                                 │
│  ├─ verify_math()    → SymPy            │
│  ├─ verify_logic()   → Z3 Solver        │
│  ├─ verify_code()    → AST Analysis     │
│  └─ verify_sql()     → Pattern Match    │
└─────────────────────────────────────────┘
```

---

## Use Cases

| Without QWED-MCP | With QWED-MCP |
|------------------|---------------|
| Claude calculates → may hallucinate | Claude calls `verify_math()` → 100% correct |
| Claude writes SQL → may be insecure | Claude calls `verify_sql()` → injection detected |
| Claude reasons → may be illogical | Claude calls `verify_logic()` → proven with Z3 |
| Claude generates code → may be unsafe | Claude calls `verify_code()` → security checked |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QWED_LOG_LEVEL` | Logging level | `INFO` |

---

## Development

```bash
# Clone
git clone https://github.com/QWED-AI/qwed-mcp.git
cd qwed-mcp

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/
```

---

## Links

- **Documentation:** [docs.qwedai.com](https://docs.qwedai.com)
- **QWED Core:** [QWED-AI/qwed-verification](https://github.com/QWED-AI/qwed-verification)
- **MCP Protocol:** [modelcontextprotocol.io](https://modelcontextprotocol.io)

---

## License

Apache 2.0 - See [LICENSE](LICENSE)
