"""
QWED-MCP Python Client Example

Connects to QWED-MCP over stdio and calls its two tools:

- execute_python_code: runs Python code after the allowlist admission check;
- verification_status: reads the result of a job started with background=True.

Code execution is off unless the server's environment sets
QWED_MCP_TRUSTED_CODE_EXECUTION=true. This example sets it for the server it
starts. Admitted code runs with the server's privileges, so only enable it
where that is acceptable.
"""

import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# The claim is wrong on purpose: 14356.29 is what annual compounding gives.
# Quarterly compounding gives 14499.48, so the check prints False.
COMPOUND_INTEREST = """
from decimal import Decimal, ROUND_HALF_UP

principal = Decimal("10000")
rate = Decimal("0.075")
n, years = 4, 5
amount = principal * (1 + rate / n) ** (n * years)
amount = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
print("amount:", amount)
print("claim of 14356.29 holds:", amount == Decimal("14356.29"))
"""

SYLLOGISM = """
from itertools import product

# Premises: mammal -> warm_blooded, dolphin -> mammal.
# Conclusion: dolphin -> warm_blooded. Check every assignment.
def implies(a, b):
    return (not a) or b

counterexamples = [
    (dolphin, mammal, warm)
    for dolphin, mammal, warm in product([False, True], repeat=3)
    if implies(mammal, warm) and implies(dolphin, mammal)
    and not implies(dolphin, warm)
]
print("valid:", not counterexamples)
"""

# Refused before it runs: os is not on the allowlist.
REFUSED = """
import os
print(os.listdir("."))
"""


def _text(result) -> str:
    return "\n".join(part.text for part in result.content if hasattr(part, "text"))


async def main():
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "qwed_mcp.server"],
        env={"QWED_MCP_TRUSTED_CODE_EXECUTION": "true"},
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools:", ", ".join(tool.name for tool in tools.tools))

            print("\n1. Compound interest with exact decimal arithmetic")
            result = await session.call_tool(
                "execute_python_code", arguments={"code": COMPOUND_INTEREST}
            )
            print(_text(result))

            print("\n2. A syllogism checked over every truth assignment")
            result = await session.call_tool(
                "execute_python_code", arguments={"code": SYLLOGISM}
            )
            print(_text(result))

            print("\n3. Code outside the allowlist is refused, with the reason")
            result = await session.call_tool(
                "execute_python_code", arguments={"code": REFUSED}
            )
            print(_text(result))

            print("\n4. A background job, read back with verification_status")
            result = await session.call_tool(
                "execute_python_code",
                arguments={"code": COMPOUND_INTEREST, "background": True},
            )
            message = _text(result)
            print(message)
            job_id = message.split("request ", 1)[1].split(".", 1)[0]
            for _ in range(20):
                await asyncio.sleep(0.5)
                status = await session.call_tool(
                    "verification_status", arguments={"job_id": job_id}
                )
                status_text = _text(status)
                # "Status: queued..." and "Status: running..." are not final.
                if not status_text.endswith("..."):
                    break
            print(status_text)


if __name__ == "__main__":
    asyncio.run(main())
