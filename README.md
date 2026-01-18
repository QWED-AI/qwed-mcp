# QWED-MCP

[![PyPI](https://img.shields.io/pypi/v/qwed-mcp?color=blue&label=PyPI)](https://pypi.org/project/qwed-mcp/)
[![Tests](https://github.com/QWED-AI/qwed-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-mcp/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green)](https://modelcontextprotocol.io)
[![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-mcp?style=social)](https://github.com/QWED-AI/qwed-mcp)
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification#%EF%B8%8F-what-does-verified-by-qwed-mean)

**MCP Server for QWED Verification** — Bring deterministic verification to Claude Desktop, VS Code, and any MCP-compatible AI assistant.

> 📚 **Full Documentation:** [docs.qwedai.com/mcp](https://docs.qwedai.com/docs/mcp/overview)

---

## ⚡ Quick Install

```bash
pip install qwed-mcp
```

---

## 🚀 Setup with Claude Desktop

### Step 1: Find your config file

| OS | Path |
|----|------|
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

### Step 2: Add QWED-MCP

**macOS/Linux:**
```json
{
  "mcpServers": {
    "qwed-verification": {
      "command": "qwed-mcp"
    }
  }
}
```

**Windows (use python -m):**
```json
{
  "mcpServers": {
    "qwed-verification": {
      "command": "python",
      "args": ["-m", "qwed_mcp.server"]
    }
  }
}
```

### Step 3: Restart Claude Desktop

Quit completely (system tray → Quit) and reopen.

### Step 4: Test it!

Ask Claude:
> "Verify the derivative of x³ equals 3x² using verify_math"

---

## 🔧 Available Tools

| Tool | Engine | Use Case |
|------|--------|----------|
| `verify_math` | SymPy | Verify calculations, derivatives, integrals |
| `verify_logic` | Z3 Solver | Prove logical arguments, validate reasoning |
| `verify_code` | AST Analysis | Detect security vulnerabilities |
| `verify_sql` | Pattern Matching | SQL injection detection |

---

## 💡 Example Prompts for Claude

### Financial Calculations
```
A bank says: "Invest $10,000 at 7.5% compounded quarterly for 5 years = $14,356.29"
Use verify_math to check using A = P(1 + r/n)^(nt)
```

### Loan EMI Verification
```
Verify: ₹10,00,000 loan at 9% for 5 years = EMI of ₹20,758
Use the EMI formula: EMI = P × r × (1+r)^n / ((1+r)^n - 1)
```

### Logic Verification
```
Use verify_logic:
Premises: "All mammals are warm-blooded", "Dolphins are mammals"
Conclusion: "Dolphins are warm-blooded"
```

### Code Security Check
```
Use verify_code to check this for security issues:

def run_command(cmd):
    os.system(cmd)
    return eval(get_response())
```

### SQL Injection Detection
```
Use verify_sql to check:
SELECT * FROM accounts WHERE user_id = '1' OR '1'='1'
```

---

## 🏗️ How It Works

```
┌───────────────────────────────────────────┐
│      Claude Desktop / VS Code             │
│           (MCP Client)                    │
└─────────────────┬─────────────────────────┘
                  │ MCP Protocol (JSON-RPC)
                  ▼
┌───────────────────────────────────────────┐
│           QWED-MCP Server                 │
├───────────────────────────────────────────┤
│  verify_math()    → SymPy (symbolic math) │
│  verify_logic()   → Z3 SMT Solver         │
│  verify_code()    → Python AST Analysis   │
│  verify_sql()     → Regex Pattern Match   │
└───────────────────────────────────────────┘
```

---

## 🎯 Why QWED-MCP?

| Without QWED-MCP | With QWED-MCP |
|------------------|---------------|
| LLM calculates → 95% correct | `verify_math()` → **100% correct** |
| LLM writes SQL → might inject | `verify_sql()` → **injection detected** |
| LLM reasons → might be wrong | `verify_logic()` → **formally proven** |
| LLM codes → might be unsafe | `verify_code()` → **security checked** |

---

## 📁 Examples

See the [`examples/`](./examples) folder for:
- Python client usage
- Sample verification scripts
- Integration examples

---

## 🛠️ Development

```bash
# Clone
git clone https://github.com/QWED-AI/qwed-mcp.git
cd qwed-mcp

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Format code
black src/
```

---

## 📖 Documentation

| Resource | Link |
|----------|------|
| Full Docs | [docs.qwedai.com/mcp](https://docs.qwedai.com/docs/mcp/overview) |
| Tools Reference | [docs.qwedai.com/mcp/tools](https://docs.qwedai.com/docs/mcp/tools) |
| Examples | [docs.qwedai.com/mcp/examples](https://docs.qwedai.com/docs/mcp/examples) |
| Troubleshooting | [docs.qwedai.com/mcp/troubleshooting](https://docs.qwedai.com/docs/mcp/troubleshooting) |
| MCP Protocol | [modelcontextprotocol.io](https://modelcontextprotocol.io) |

---

## 🔗 Related Projects

- **QWED Core** — [github.com/QWED-AI/qwed-verification](https://github.com/QWED-AI/qwed-verification)
- **QWED-UCP** — [github.com/QWED-AI/qwed-ucp](https://github.com/QWED-AI/qwed-ucp)
- **QWED Open Responses** — [github.com/QWED-AI/qwed-open-responses](https://github.com/QWED-AI/qwed-open-responses)

---

## 📄 License

Apache 2.0 — See [LICENSE](LICENSE)

---

<p align="center">
  <b>Built by <a href="https://qwedai.com">QWED AI</a></b><br>
  <i>Making AI outputs trustworthy through formal verification</i>
</p>