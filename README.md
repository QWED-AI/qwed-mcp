<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/qwed-lockup-white.svg">
    <img src="assets/qwed-lockup.svg" alt="QWED" height="56">
  </picture>
  <h1>QWED-MCP 🔌</h1>
  <h3>Deterministic Verification for Claude Desktop & VS Code</h3>

[![PyPI](https://img.shields.io/pypi/v/qwed-mcp?color=blue&label=PyPI)](https://pypi.org/project/qwed-mcp/)
[![Docker Verified](https://img.shields.io/badge/Docker-Verified_Publisher-blue.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/qwedai/qwed-mcp)
[![Docker Scout](https://img.shields.io/badge/Docker-Scout_Analyzed-1D63ED.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/qwedai/qwed-mcp/tags)
[![Cloudflare](https://img.shields.io/badge/Protected_by-Cloudflare-F38020?style=flat&logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![Snyk Security](https://snyk.io/test/github/QWED-AI/qwed-mcp/badge.svg)](https://snyk.io/test/github/QWED-AI/qwed-mcp)
[![Docs by Mintlify](https://img.shields.io/badge/Docs_by-Mintlify-0f1117?style=flat&logo=mintlify&logoColor=white)](https://docs.qwedai.tech)
[![Deploys by Netlify](https://img.shields.io/badge/Deploys_by-Netlify-00C7B7?style=flat&logo=netlify&logoColor=white)](https://www.netlify.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green)](https://modelcontextprotocol.io)
[![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-mcp?style=social)](https://github.com/QWED-AI/qwed-mcp)
[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-verification#%EF%B8%8F-what-does-verified-by-qwed-mean)

</div>

**MCP Server for QWED Verification** — Bring deterministic verification to Claude Desktop, VS Code, and any MCP-compatible AI assistant.

> 📚 **Full Documentation:** [docs.qwedai.tech/mcp](https://docs.qwedai.tech/mcp/overview)

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

Code execution is off by default: until the server administrator sets `QWED_MCP_TRUSTED_CODE_EXECUTION=true` in the server's environment (for example with an `"env": {"QWED_MCP_TRUSTED_CODE_EXECUTION": "true"}` entry next to `"command"` above), `execute_python_code` answers `BLOCKED_ADMIN_POLICY` and runs nothing. Admitted code then runs with the server's privileges, so only turn it on where that is acceptable.

Ask Claude:
> "Write a python script that checks a 10,000 investment at 7.5% for 5 years with the `decimal` module, and run it using `execute_python_code`."

---

## ⚠️ Migration Note: Deprecation of `verify_*` Tools

To solve "context bloat" and align with the new MCP standard (RFC-9728), all 1:1 functional tools (e.g., `verify_math`, `verify_sql`, `verify_code`) **have been removed** as of `v0.2.1`. 

They have been replaced with a single, highly capable tool:
**👉 `execute_python_code`** 

**Before:**
> "Use `verify_math` to check this formula." (Claude loads 14 different tool schemas into context)

**After:**
> "Use `execute_python_code` to write and run a script that checks..." (Claude loads 1 tool schema into context)

If you see an `"Unknown tool"` error, it means Claude is trying to use a legacy tool. Simply tell Claude: *"The `verify_*` tools are removed. Use `execute_python_code` to natively write and run a Python verification script."*

---

## 🔧 Available Tools

| Tool | Description | Use Case |
|------|-------------|----------|
| `execute_python_code` | **Subprocess Execution** | The single tool the server registers. Executes dynamically generated Python code in a subprocess with restricted environment variables, after an allowlist admission check (below). Note: Runs with server privileges; ensure inputs are trusted. |

### What code is admitted

Before any code runs, the server parses it and admits it only when every module, builtin and attribute it uses is on an allowlist (`src/qwed_mcp/engines/python_allowlist.py`):

- **Modules:** computation-only standard-library modules such as `math`, `cmath`, `decimal`, `fractions`, `statistics`, `itertools`, `functools`, `collections`, `json`, `re`, `datetime` and `random`, and in each only the listed names. Modules that reach files, the network, processes, the environment or the import system (`os`, `sys`, `subprocess`, `socket`, `pathlib`, `importlib`, `ctypes`, ...) are refused, and so is every third-party package, QWED SDK packages included.
- **Builtins:** only builtins that compute. `open`, `eval`, `exec`, `compile`, `__import__`, `getattr`, `vars`, `globals`, `type`, `input`, `breakpoint` and the rest are refused wherever they appear, so they cannot be rebound or passed on.
- **Attributes:** no special or private attribute (`__x__`, `_x`) apart from reading `__init__` and `__name__`, no frame or traceback attribute, and `str.format` only on a string literal whose fields read no attribute.

Admission is a static check of what the code can reach. It is not a proof that the code is correct, and it does not limit resource use: the execution timeout limits run time, and nothing limits memory. Refused code is reported with the reason and never runs. The output of admitted code comes from that code, so treat it as untrusted data.

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
1. Extract the financial penalties the terms state.
2. Use execute_python_code to check that each penalty stays within the stated boundaries.
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
│       └─► Allowlist admission, then run   │
└───────────────────────────────────────────┘
```

---

## 🎯 Why QWED-MCP?

> *Note: Subprocess execution provides answers/checks purely based on what the executed scripts compute. Execution itself does not guarantee injection detection. QWED SDK packages are not on the admission allowlist yet, so scripts that import them are refused (see [What code is admitted](#what-code-is-admitted)).*

| Without QWED-MCP | With QWED-MCP |
|------------------|---------------|
| LLM calculates in its reply → may slip or round | Script computes it with `decimal` or `fractions` → **exact arithmetic, shown in the output** |
| LLM writes code → might reach files, network or processes | Code is checked against the allowlist first → **refused before it runs** |

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

### ✅ Released (v0.3.0)
- [x] `execute_python_code` admits code by allowlist instead of a denylist: only listed modules, builtins and attributes (see [What code is admitted](#what-code-is-admitted))
- [x] Only UTF-8 source encodings are admitted, and admitted code runs in isolated mode (`python -I`). Fixes GHSA-425c-p25c-qxwh and GHSA-qj7c-h9rh-qppc
- [x] Math engine refuses unknown operations, and expressions whose evaluation would exceed a size bound, before SymPy evaluates them
- [x] Logic engine reports `PROVEN`, `DISPROVEN` or `UNVERIFIABLE`; a statement it cannot read is `UNVERIFIABLE`
- [x] SQL engine parses the query with sqlglot instead of matching patterns, and the code engine's `sql` branch gives the same verdict
- [x] Skill provenance: registries are allowlisted by default, and a digest is checked against the skill's content when the content is supplied. A manifest-only check, such as the server's startup check, does not prove that the content matches the digest (`digest_verified` is false)
- [x] Dependencies: declares `anyio` and `sqlglot`; no longer installs `qwed-finance` or `qwed-ucp`; no longer declares `httpx` directly (`mcp` still installs it)
- [x] Release pipeline: actions pinned by SHA, publishing gated on CI and image scans, Docker image with Ubuntu security updates and pinned build inputs

#### Upgrading from 0.2.x
- Code that 0.2.x ran may now be refused: anything that imports a module outside the allowlist (`os`, `pathlib`, `requests`, QWED SDK packages and other third-party packages), calls `open`, `eval`, `getattr` or another refused builtin, or reads a private or special attribute. The refusal lists the reason.
- `qwed-finance` and `qwed-ucp` are no longer installed with qwed-mcp. Install them yourself if your own code imports them. `httpx` is no longer a direct dependency; `mcp` still installs it, but declare it in your own project if your code imports it.
- Library users: logic results carry `verification_mode`, and the math, logic and SQL engines report input they cannot decide as refused or `UNVERIFIABLE` instead of returning a verdict for it.

### ✅ Released (v0.2.3)
- [x] Context bloat resolution (RFC-9728 compatibility)
- [x] Unified `execute_python_code` environment
- [x] Secure process isolation (env-restricted) and robust timeouts
- [x] Claude Desktop integration
- [x] Windows/macOS/Linux support
- [x] Hardened math sandbox: AST allowlist for expression evaluation (GHSA-2p69-jpm6-jrxh)
- [x] `qwedai.com` removed from the trusted skill source domains (#71)
- [x] Requires `mcp>=1.30.0,<2`. MCP SDK 1.30.0 patches GHSA-84m7-p3x7-pcfv, GHSA-rwrf-2pqf-9j8j and GHSA-5h93-6whr-6q8j; for GHSA-w4fh-qvv9-3v23, HTTP servers that use the SDK's bearer authentication must also set `validate_token_resource=True`. qwed-mcp runs over stdio and uses neither the HTTP transports nor bearer authentication. MCP SDK 2.x removed the server API qwed-mcp uses
- [x] Reports its own version to MCP clients during initialisation

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
| Full Docs | [docs.qwedai.tech/mcp](https://docs.qwedai.tech/mcp/overview) |
| Tools Reference | [docs.qwedai.tech/mcp/tools](https://docs.qwedai.tech/mcp/tools) |
| Examples | [docs.qwedai.tech/mcp/examples](https://docs.qwedai.tech/mcp/examples) |
| Troubleshooting | [docs.qwedai.tech/mcp/troubleshooting](https://docs.qwedai.tech/mcp/troubleshooting) |
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
  <b>Built by <a href="https://qwedai.tech">QWED AI</a></b><br>
  <i>Making AI outputs trustworthy through formal verification</i>
</p>
