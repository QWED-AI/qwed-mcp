"""
QWED-MCP Server

Main MCP server implementation with QWED verification tools.
"""

import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .tools import register_tools

# Configure logging to stderr (required for MCP)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("qwed-mcp")

# Initialize MCP server
mcp = Server("qwed-verification")


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
