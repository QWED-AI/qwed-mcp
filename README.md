<div align="center">
  <img src="assets/logo.png" alt="QWED Logo - AI Verification Engine" width="80" height="80">
  <h1>QWED-MCP 🔌</h1>
  <h3>Deterministic Verification for Claude Desktop & VS Code</h3>

[![PyPI](https://img.shields.io/pypi/v/qwed-mcp?color=blue&label=PyPI)](https://pypi.org/project/qwed-mcp/)
[![Docker Verified](https://img.shields.io/badge/Docker-Verified_Publisher-blue.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/qwedai/qwed-verification)
[![Docker Scout](https://img.shields.io/badge/Docker-Scout_Analyzed-1D63ED.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/qwedai/qwed-verification/tags)
[![Cloudflare](https://img.shields.io/badge/Protected_by-Cloudflare-F38020?style=flat&logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![Snyk Security](https://snyk.io/test/github/QWED-AI/qwed-mcp/badge.svg)](https://snyk.io/test/github/QWED-AI/qwed-mcp)
[![Docs by Mintlify](https://img.shields.io/badge/Docs_by-Mintlify-0f1117?style=flat&logo=mintlify&logoColor=white)](https://docs.qwedai.com)
[![Deploys by Netlify](https://img.shields.io/badge/Deploys_by-Netlify-00C7B7?style=flat&logo=netlify&logoColor=white)](https://www.netlify.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green)](https://modelcontextprotocol.io)
[![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-mcp?style=social)](https://github.com/QWED-AI/qwed-mcp)
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification#%EF%B8%8F-what-does-verified-by-qwed-mean)

</div>

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
> "Write a python script that verifies a 10,000 investment at 7.5% for 5 years using the `qwed_new` math engine, and run it using `execute_python_code`."

---

## ⚠️ Migration Note: Deprecation of `verify_*` Tools

To solve "context bloat" and align with the new MCP standard (RFC-9728), all 1:1 functional tools (e.g., `verify_math`, `verify_sql`, `verify_code`) **have been removed** as of `v0.2.1`. 

They have been replaced with a single, highly capable tool:
**👉 `execute_python_code`** 

**Before:**
> "Use `verify_math` to check this formula." (Claude loads 14 different tool schemas into context)

**After:**
> "Use `execute_python_code` to write and run a script that imports `qwed_new.engines.math_engine` to verify..." (Claude loads 1 tool schema into context)

If you see an `"Unknown tool"` error, it means Claude is trying to use a legacy tool. Simply tell Claude: *"The `verify_*` tools are removed. Use `execute_python_code` to natively write and run a Python verification script."*

---

## 🔧 Available Tools

| Tool | Description | Use Case |
|------|-------------|----------|
| `execute_python_code` | **Subprocess Execution** | The single entrypoint for all QWED capabilities. Executes dynamically generated Python code in a subprocess with restricted environment variables. Note: Runs with server privileges; ensure inputs are trusted. |

---

## 💡 Example Prompts for Claude

> **Note:** Claude already knows how to use QWED natively via standard Python imports.

### Financial Calculations
```text
A bank says: "Invest $10,000 at 7.5% compounded quarterly for 5 years = $14,356.29"
Please write a short Python script using the standard compound interest formula to verify this, and run it with execute_python_code.
```

### Loan EMI Verification
```text
Verify: ₹10,00,000 loan at 9% for 5 years = EMI of ₹20,758
Write a python script importing necessary tools to verify this EMI calculation, and execute it using execute_python_code.
```

### Complex Reasoning Workflows (The Power of Python)
```text
Read the user terms in the attached document. 
1. Use execute_python_code to extract and verify the legal clauses using qwed_legal.
2. In the same script, verify if the referenced financial penalties align with the allowed boundaries.
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
│ execute_python_code()                     │
│  └─► Subprocess Execution (Restricted Env)│
│       └─► Native QWED library execution   │
└───────────────────────────────────────────┘
```

---

## 🎯 Why QWED-MCP?

> *Note: Subprocess execution provides answers/checks purely based on what QWED SDK methods are invoked inside the executed scripts. Execution itself does not guarantee injection detection without specific SDK calls.*

| Without QWED-MCP | With QWED-MCP |
|------------------|---------------|
| LLM calculates → 95% correct | Executes Python script calling `qwed_finance` → **100% correct** |
| LLM writes SQL → might inject | Script uses `qwed_new` analyzer → **injection detected** |
| LLM reasons → might be wrong | Z3 solver executed via SDK → **formally proven** |
| LLM codes → might be unsafe | AST check script executed → **security checked** |

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
┌───────────────────┐     ┌───────────────────────┐     ┌───────────────────┐
│      Claude       │     │       QWED-MCP        │     │  Verified Answer  │
│ "What's d/dx x³?" │ ──► │ execute_python_code() │ ──► │      "3x²" ✓      │
│ "Write script to  │     │ Runs SymPy natively   │     │ (STDOUT Captured) │
│ check."           │     └───────────────────────┘     └───────────────────┘
└───────────────────┘
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

### ✅ Released (v0.2.2)
- [x] Context bloat resolution (RFC-9728 compatibility)
- [x] Unified `execute_python_code` environment
- [x] Secure process isolation (env-restricted) and robust timeouts
- [x] Claude Desktop integration
- [x] Windows/macOS/Linux support
- [x] Hardened math sandbox: AST allowlist for expression evaluation (GHSA-2p69-jpm6-jrxh)

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
