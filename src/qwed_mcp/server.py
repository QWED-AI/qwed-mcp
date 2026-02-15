"""
QWED-MCP Server

Main MCP server implementation with QWED verification tools.
"""

import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
import sentry_sdk
import os

from .tools import register_tools

# Configure logging to stderr (required for MCP)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("qwed-mcp")

# Initialize Sentry (if DSN provided)
# Source: Leveraging Open Source Credits
if os.getenv("SENTRY_DSN"):
    sentry_sdk.init(
        dsn=os.getenv("SENTRY_DSN"),
        traces_sample_rate=1.0,
        environment="production"
    )

# Initialize MCP server
mcp = Server("qwed-verification")


def track_verification(tool_name: str, result: dict):
    """
    Logs verification attempts. Blocked attempts are Security Events.
    """
    # Start a transaction for Sentry tracing
    with sentry_sdk.start_transaction(op="verification", name=tool_name):
        # Set tags for filtering in Sentry dashboard
        sentry_sdk.set_tag("verified", result.get("verified", False))
        sentry_sdk.set_tag("tool", tool_name)
        
        if not result.get("verified"):
            # Log as WARNING to populate the "Hallucination Dashboard"
            # This is the "Security Event" monitoring layer
            error_msg = result.get("error", "Unknown Error")
            sentry_sdk.capture_message(
                f"QWED Blocked: {tool_name} - {error_msg}",
                level="warning"
            )
            # Add context for debugging
            sentry_sdk.set_context("verification_details", result)


def create_server() -> Server:
    """Create and configure the QWED MCP server."""
    # Register all verification tools
    register_tools(mcp)
    
    logger.info("QWED-MCP server initialized with verification tools")
    return mcp


async def run_server():
    """Run the MCP server using stdio transport."""
    server = create_server()
    
    async with stdio_server() as (read_stream, write_stream):
        logger.info("Starting QWED-MCP server...")
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main():
    """Entry point for the qwed-mcp command."""
    import asyncio
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
