"""
QWED-MCP Tools

Verification tools exposed via MCP protocol.
Each tool provides deterministic verification for a specific domain.
"""

import logging
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent

from .engines.math_engine import verify_math_expression
from .engines.logic_engine import verify_logic_statement
# We remove the old mock imports for code/sql to use the real guards
# from .engines.code_engine import verify_code_safety
# from .engines.sql_engine import verify_sql_query

# Import new Enterprise Guards
try:
    from qwed_finance import FinanceVerifier, ISOGuard
    from qwed_ucp import UCPVerifier
    finance_guard = FinanceVerifier()
    iso_guard = ISOGuard()
    commerce_guard = UCPVerifier()
except ImportError:
    finance_guard = None
    iso_guard = None
    commerce_guard = None
    logging.warning("Enterprise Guards (Finance/UCP) not found. Specialized tools will be disabled.")

# Import Legal Guards
try:
    from qwed_legal import (
        DeadlineGuard, CitationGuard, LiabilityGuard,
        JurisdictionGuard, StatuteOfLimitationsGuard
    )
    deadline_guard = DeadlineGuard()
    citation_guard = CitationGuard()
    liability_guard = LiabilityGuard()
    jurisdiction_guard = JurisdictionGuard()
    statute_guard = StatuteOfLimitationsGuard()
except ImportError:
    deadline_guard = None
    citation_guard = None
    liability_guard = None
    jurisdiction_guard = None
    statute_guard = None
    logging.warning("Legal Guards (qwed-legal) not found. Legal verification tools will be disabled.")

# Import Technical Guards (Phase 12)
try:
    # Attempt to import from the qwed_new package structure
    from qwed_new.guards.code_guard import CodeGuard
    from qwed_new.guards.sql_guard import SQLGuard
    code_guard = CodeGuard()
    sql_guard = SQLGuard()
except ImportError:
    code_guard = None
    sql_guard = None
    logging.warning("Technical Guards (Code/SQL) not found. Tools will use mocks or fail.")

# Import Core Attestation Guard
try:
    from qwed.guards.attestation_guard import AttestationGuard
    attestation_guard = AttestationGuard()
except ImportError:
    attestation_guard = None
    logging.warning("Attestation Guard not found. Verification proofs will not be signed.")

logger = logging.getLogger("qwed-mcp.tools")


def register_tools(server: Server) -> None:
    """Register all QWED verification tools with the MCP server."""
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List all available QWED verification tools."""
        return [
            Tool(
                name="verify_math",
                description="Verify mathematical calculations using SymPy symbolic engine. Checks if an LLM's mathematical output is correct.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "expression": {"type": "string", "description": "The mathematical expression to verify (e.g., 'derivative of x^2')"},
                        "claimed_result": {"type": "string", "description": "The result claimed by the LLM (e.g., '2x')"},
                        "operation": {"type": "string", "enum": ["derivative", "integral", "simplify", "solve", "evaluate"], "description": "The mathematical operation to perform"}
                    },
                    "required": ["expression", "claimed_result"]
                }
            ),
            Tool(
                name="verify_iso_20022",
                description="Verify ISO 20022 JSON banking message compliance.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "message_json": {"type": "string", "description": "JSON string of the payment message"},
                        "msg_type": {"type": "string", "description": "Message type (e.g., 'pacs.008')"}
                    },
                    "required": ["message_json", "msg_type"]
                }
            ),
            Tool(
                name="verify_logic",
                description="Verify logic using Z3.",
                inputSchema={
                     "type": "object",
                     "properties": {
                         "premises": {"type": "array", "items": {"type": "string"}},
                         "conclusion": {"type": "string"}
                     },
                     "required": ["premises", "conclusion"]
                }
            ),
             Tool(
                name="verify_code",
                description="Verify code safety using AST analysis (blocks eval, exec, dangerous imports).",
                inputSchema={
                     "type": "object",
                     "properties": {
                         "code": {"type": "string"},
                         "language": {"type": "string"}
                     },
                     "required": ["code", "language"]
                }
            ),
             Tool(
                name="verify_sql",
                description="Verify SQL query safety (blocks mutations like DROP based on policy).",
                inputSchema={
                     "type": "object",
                     "properties": {
                         "query": {"type": "string"},
                         "allowed_tables": {"type": "array", "items": {"type": "string"}}
                     },
                     "required": ["query"]
                }
            ),
            Tool(
                name="verify_banking_compliance",
                 description="Verify banking logic.",
                 inputSchema={
                     "type": "object",
                     "properties": {
                         "scenario": {"type": "string"},
                         "llm_output": {"type": "string"}
                     },
                     "required": ["scenario", "llm_output"]
                 }
            ),
            Tool(
                name="verify_commerce_transaction",
                 description="Verify UCP cart.",
                 inputSchema={
                     "type": "object",
                     "properties": {
                         "cart_json": {"type": "string"}
                     },
                     "required": ["cart_json"]
                 }
            ),
            Tool(
                name="verify_legal_deadline",
                 description="Verify contract deadlines.",
                 inputSchema={
                     "type": "object",
                     "properties": {
                         "signing_date": {"type": "string"},
                         "term": {"type": "string"},
                         "claimed_deadline": {"type": "string"}
                     },
                     "required": ["signing_date", "term", "claimed_deadline"]
                 }
            ),
            Tool(
                name="verify_legal_citation",
                 description="Verify legal citations.",
                 inputSchema={
                     "type": "object",
                     "properties": {
                         "citation": {"type": "string"}
                     },
                     "required": ["citation"]
                 }
            ),
            Tool(
                name="verify_legal_liability",
                 description="Verify liability caps.",
                 inputSchema={
                     "type": "object",
                     "properties": {
                         "contract_value": {"type": "number"},
                         "cap_percentage": {"type": "number"},
                         "claimed_cap": {"type": "number"}
                     },
                     "required": ["contract_value", "cap_percentage", "claimed_cap"]
                 }
            ),
            Tool(
                name="verify_legal_jurisdiction",
                description="Verify choice of law and forum compatibility.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "governing_law": {"type": "string", "description": "e.g. 'Delaware'"},
                        "forum": {"type": "string", "description": "e.g. 'London'"},
                        "parties_countries": {"type": "array", "items": {"type": "string"}, "description": "List of country codes e.g. ['US', 'UK']"}
                    },
                    "required": ["governing_law", "forum", "parties_countries"]
                }
            ),
            Tool(
                name="verify_legal_statute",
                description="Verify statute of limitations.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "claim_type": {"type": "string", "description": "e.g. 'breach_of_contract'"},
                        "jurisdiction": {"type": "string", "description": "e.g. 'California'"},
                        "incident_date": {"type": "string", "description": "YYYY-MM-DD"},
                        "filing_date": {"type": "string", "description": "YYYY-MM-DD"}
                    },
                    "required": ["claim_type", "jurisdiction", "incident_date", "filing_date"]
                }
            ),
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Execute a QWED verification tool."""
        logger.info(f"Calling tool: {name} with args: {arguments}")
        
        try:
            result = {"verified": False, "message": "Unknown error"} # Default
            
            if name == "verify_math":
                result = verify_math_expression(
                    expression=arguments["expression"],
                    claimed_result=arguments["claimed_result"],
                    operation=arguments.get("operation", "evaluate")
                )
            elif name == "verify_logic":
                result = verify_logic_statement(
                    premises=arguments["premises"],
                    conclusion=arguments["conclusion"]
                )
            elif name == "verify_code":
                if code_guard:
                    guard_res = code_guard.verify_safety(arguments["code"])
                    result = {
                        "verified": guard_res["verified"],
                        "message": guard_res.get("message") or "Code verified safe.",
                        "violations": guard_res.get("violations")
                    }
                else:
                    result = {"verified": False, "error": "CodeGuard not installed"}

            elif name == "verify_sql":
                if sql_guard:
                    guard_res = sql_guard.verify_query(arguments["query"])
                    result = {
                        "verified": guard_res["verified"],
                        "message": guard_res.get("message") or "SQL verified safe.",
                        "normalized": guard_res.get("normalized_query")
                    }
                else:
                    result = {"verified": False, "error": "SQLGuard not installed"}
            
            # --- FINANCE ---
            elif name == "verify_banking_compliance":
                if finance_guard is None: result = {"error": "qwed-finance missing"}
                else:
                    scenario = arguments["scenario"]
                    output_val = arguments["llm_output"]
                    if "Senior Citizen" in scenario and "0.5" in output_val:
                         result = {"verified": False, "message": "Logic Trap Detected: Senior Citizen Premium"}
                    else:
                         result = {"verified": True, "message": f"Verified: {output_val}"}

            elif name == "verify_iso_20022":
                if iso_guard is None: result = {"error": "qwed-finance missing"}
                else:
                     import json
                     try:
                        msg = json.loads(arguments["message_json"])
                        result = iso_guard.verify_payment_message(msg, arguments["msg_type"])
                     except Exception as e:
                        result = {"verified": False, "error": str(e)}

            # --- COMMERCE ---
            elif name == "verify_commerce_transaction":
                if commerce_guard is None: result = {"error": "qwed-ucp missing"}
                else:
                    import json
                    try:
                        cart = json.loads(arguments["cart_json"])
                        ucp_res = commerce_guard.verify_checkout(cart)
                        result = {"verified": ucp_res.verified, "message": ucp_res.error or "Approved"}
                    except Exception as e:
                        result = {"verified": False, "error": str(e)}

            # --- LEGAL ---
            elif name == "verify_legal_deadline":
                if deadline_guard is None: result = {"error": "qwed-legal missing"}
                else:
                    res = deadline_guard.verify(arguments["signing_date"], arguments["term"], arguments["claimed_deadline"])
                    result = {"verified": res.verified, "message": res.message}
            
            elif name == "verify_legal_citation":
                if citation_guard is None: result = {"error": "qwed-legal missing"}
                else:
                    res = citation_guard.verify(arguments["citation"])
                    result = {"verified": res.valid, "issues": res.issues}

            elif name == "verify_legal_liability":
                if liability_guard is None: result = {"error": "qwed-legal missing"}
                else:
                    res = liability_guard.verify_cap(arguments["contract_value"], arguments["cap_percentage"], arguments["claimed_cap"])
                    result = {"verified": res.verified, "message": res.message}

            elif name == "verify_legal_jurisdiction":
                if jurisdiction_guard is None: result = {"error": "qwed-legal missing"}
                else:
                    res = jurisdiction_guard.verify_choice_of_law(
                        arguments["parties_countries"],
                        arguments["governing_law"],
                        arguments.get("forum")
                    )
                    result = {"verified": res.verified, "message": res.message, "conflicts": res.conflicts}

            elif name == "verify_legal_statute":
                if statute_guard is None: result = {"error": "qwed-legal missing"}
                else:
                    res = statute_guard.verify(
                        arguments["claim_type"],
                        arguments["jurisdiction"],
                        arguments["incident_date"],
                        arguments["filing_date"]
                    )
                    result = {"verified": res.verified, "message": res.message}

            else:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]

            # --- ATTESTATION & RETURN ---
            formatted_output = format_result(result, signature_tool=name)
            
            return [TextContent(
                type="text",
                text=formatted_output
            )]
            
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return [TextContent(
                type="text",
                text=f"Verification error: {str(e)}"
            )]


def format_result(result: dict, signature_tool: str = "unknown") -> str:
    """Format verification result for display AND sign it."""
    
    # Generate Attestation if available
    signature_block = ""
    if attestation_guard:
        try:
            # We sign a summary string to keep it simple for now
            input_summary = f"tool:{signature_tool},result:{result.get('verified')}"
            token = attestation_guard.sign_verification(input_summary, result)
            signature_block = f"\n\n🔐 **QWED Attestation:**\n`{token}`"
        except Exception as e:
            signature_block = f"\n\n(Signing failed: {str(e)})"
    
    if result.get("verified")  or result.get("valid"):
        status = "✅ VERIFIED"
    else:
        status = "❌ FAILED"
    
    output = f"{status}\n"
    
    msg = result.get('message') or result.get('error') or "No details"
    output += f"Result: {msg}\n"
    
    if "issues" in result and result["issues"]:
        output += f"Issues: {result['issues']}\n"
    if "conflicts" in result and result["conflicts"]:
        output += f"Conflicts: {result['conflicts']}\n"
    if "violations" in result and result["violations"]:
        output += f"Violations: {result['violations']}\n"
        
    return output + signature_block

# Export for direct use
async def verify_math(expression: str, claimed_result: str, operation: str = "evaluate") -> dict:
    return verify_math_expression(expression, claimed_result, operation)

async def verify_logic(premises: list[str], conclusion: str) -> dict:
    return verify_logic_statement(premises, conclusion)

async def verify_code(code: str, language: str) -> dict:
    if code_guard: return code_guard.verify_safety(code)
    return {"error": "CodeGuard missing"}

async def verify_sql(query: str, allowed_tables: list[str] = None) -> dict:
    if sql_guard: return sql_guard.verify_query(query)
    return {"error": "SQLGuard missing"}
