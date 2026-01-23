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

## 💡 What QWED-MCP Is (and Isn't)

### ✅ QWED-MCP IS:
- **MCP Server** that adds verification tools to Claude Desktop and VS Code
- **Deterministic** — uses SymPy (math), Z3 (logic), AST (code) for exact verification
- **Open source** — works with any MCP-compatible AI assistant
- **A safety layer** — catches LLM hallucinations in real-time

### ❌ QWED-MCP is NOT:
- ~~A replacement for Claude~~ — it enhances Claude with verification tools
- ~~A chatbot~~ — it's a backend server that Claude calls
- ~~Internet-connected~~ — all verification happens locally
- ~~A fine-tuned model~~ — uses symbolic engines, not ML

> **Think of QWED-MCP as giving Claude a "calculator" for math and a "theorem prover" for logic.**
> 
> Claude reasons. QWED-MCP verifies.

---

## 🆚 How We're Different from Other MCP Servers

| Aspect | Other MCP Servers | QWED-MCP |
|--------|-------------------|----------|
| **Purpose** | Connect to APIs, databases, files | Verify LLM outputs |
| **Approach** | Fetch external data | Compute deterministic proofs |
| **Engines** | API wrappers | SymPy, Z3, AST analyzers |
| **Accuracy** | Depends on data source | 100% mathematically proven |
| **Offline** | Often need internet | Fully local, no APIs |

### With Claude Desktop
```
┌───────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│      Claude       │ ──► │    QWED-MCP     │ ──► │  Verified Answer │
│ "What's d/dx x³?" │     │ verify_math()   │     │    "3x²" ✓       │
└───────────────────┘     └─────────────────┘     └──────────────────┘
```

---

## 🔒 Security & Privacy

> **All verification happens locally. Nothing is sent to external servers.**

| Concern | QWED-MCP Approach |
|---------|-------------------|
| **Data Transmission** | ❌ No external API calls |
| **Storage** | ❌ Nothing logged or stored |
| **Dependencies** | ✅ Local engines (SymPy, Z3) |
| **Code Analysis** | ✅ Your code never leaves your machine |

**Perfect for:**
- Enterprises with strict security policies
- Air-gapped development environments
- Sensitive code review workflows

---

## ❓ FAQ

<details>
<summary><b>Is QWED-MCP free?</b></summary>

Yes! Open source under Apache 2.0. Use it commercially, modify it, distribute it.
</details>

<details>
<summary><b>Does it work with VS Code Copilot?</b></summary>

QWED-MCP works with any MCP-compatible client. VS Code with Claude extension supports MCP, so yes!
</details>

<details>
<summary><b>Do I need an API key?</b></summary>

No. QWED-MCP runs entirely locally. No API keys, no cloud calls.
</details>

<details>
<summary><b>What's the difference between this and QWED-Core?</b></summary>

QWED-Core is the Python library. QWED-MCP wraps it as an MCP server so Claude can use it as a tool.
</details>

<details>
<summary><b>Can I add my own verification tools?</b></summary>

Yes! The server is extensible. Fork it and add your custom `@mcp.tool()` functions.
</details>

---

## 🗺️ Roadmap

### ✅ Released (v1.0.0)
- [x] `verify_math` — SymPy symbolic math
- [x] `verify_logic` — Z3 SMT solver
- [x] `verify_code` — Python AST security analysis
- [x] `verify_sql` — SQL injection detection
- [x] Claude Desktop integration
- [x] Windows/macOS/Linux support

### 🚧 In Progress
- [ ] `verify_json` — JSON Schema validation tool
- [ ] `verify_finance` — NPV/IRR/amortization tool
- [ ] Cursor IDE integration guide

### 🔮 Planned
- [ ] `verify_legal` — Deadline and liability verification
- [ ] `verify_statistics` — Hypothesis test validation
- [ ] SSE (Server-Sent Events) transport for web UIs
- [ ] TypeScript implementation

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