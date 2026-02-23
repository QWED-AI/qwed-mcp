import hashlib
import json
from datetime import datetime, timezone
from typing import Any

class AIBOMGenerator:
    """
    Generates an AI Bill of Materials (AI-BOM) for visibility into agent supply chains.
    Source: Snyk AI-SPM requirements [Source 1484].
    """
    @staticmethod
    def generate_manifest(
        llm_model: str, 
        qwed_engines_used: list[str] | None = None, 
        mcp_tools_used: list[str] | None = None
    ) -> dict[str, Any]:
        if not llm_model:
            raise ValueError("llm_model must be a non-empty string")
        qwed_engines_used = qwed_engines_used or []
        mcp_tools_used = mcp_tools_used or []
        
        bom = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "models": [{"name": llm_model, "type": "generator"}],
                "verification_engines": [{"name": engine, "type": "qwed_deterministic"} for engine in qwed_engines_used],
                "mcp_tools": [{"name": tool, "type": "action_execution"} for tool in mcp_tools_used]
            },
            "compliance": "QWED_AI_SPM_v1"
        }
        
        # Hash the canonical JSON of the BOM (excluding volatile fields like timestamp)
        bom_for_hash = bom.copy()
        del bom_for_hash["timestamp"]
        bom_hash = hashlib.sha256(
            json.dumps(bom_for_hash, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        bom["manifest_hash"] = bom_hash
        
        return bom
