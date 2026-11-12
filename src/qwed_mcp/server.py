"""
QWED-MCP Server

Main MCP server implementation with QWED verification tools.
"""

import logging
import sys
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
import sentry_sdk
import os

from ._version import __version__
from .tools import register_tools
from .security.provenance import SkillProvenanceGuard

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
# Pass the version so clients see qwed-mcp's own, not the MCP SDK's
mcp = Server("qwed-verification", version=__version__)


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


def _log_text(value: object) -> str:
    """Text from a manifest, safe to put on one log line."""
    return "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in str(value))


def verify_server_skills():
    """Verify any skills defined in the environment before starting."""
    manifest_path = os.getenv("QWED_SKILL_MANIFEST")
    if not manifest_path:
        return

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        if not isinstance(manifest, dict):
            logger.error("FATAL: Skill manifest must be a JSON object, not an array or primitive.")
            sys.exit(1)

        logger.info(f"Validating skill manifest at {manifest_path}")
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(manifest)

        if not result["verified"]:
            logger.error(
                "FATAL: Skill validation failed: %s", _log_text(result["message"])
            )
            sys.exit(1)

        logger.info(
            "Skill '%s' passed provenance checks (status: %s).",
            _log_text(result.get("skill_name", "unknown")),
            _log_text(result.get("status")),
        )
        for advisory in result.get("advisories", []):
            logger.info("Skill provenance advisory: %s", _log_text(advisory))
    except Exception as e:
        logger.error(f"FATAL: Failed to read or parse skill manifest: {e}")
        sys.exit(1)


def create_server() -> Server:
    """Create and configure the QWED MCP server."""
    # Verify skill provenance before creating server to prevent poisoned plugins
    verify_server_skills()

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
