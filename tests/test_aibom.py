import hashlib
import copy
import json
from qwed_mcp.observability.aibom import AIBOMGenerator

def test_aibom_generation_contains_required_fields():
    generator = AIBOMGenerator()
    llm = "gpt-4o"
    engines = ["qwed_tax.TaxVerifier", "qwed_legal.FairnessGuard"]
    tools = ["read_file", "write_file"]
    
    bom = generator.generate_manifest(llm, engines, tools)
    
    assert bom["compliance"] == "QWED_AI_SPM_v1"
    assert "timestamp" in bom
    assert "manifest_hash" in bom
    
    components = bom["components"]
    assert len(components["models"]) == 1
    assert components["models"][0]["name"] == "gpt-4o"
    
    assert len(components["verification_engines"]) == 2
    assert components["verification_engines"][0]["name"] == "qwed_tax.TaxVerifier"
    
    assert len(components["mcp_tools"]) == 2
    assert components["mcp_tools"][1]["name"] == "write_file"

def test_aibom_hash_is_deterministic_based_on_content():
    generator = AIBOMGenerator()
    
    bom = generator.generate_manifest("claude-3-opus", [], ["search"])
    
    assert len(bom["manifest_hash"]) == 64  # SHA256 length
    
    # Verify two calls with the same logical inputs yield the same hash
    # (timestamp does not affect the hash serialization)
    bom2 = generator.generate_manifest("claude-3-opus", [], ["search"])
    assert bom["manifest_hash"] == bom2["manifest_hash"], (
        "manifest_hash must be deterministic for identical inputs"
    )
    
    # Also verify the stored hash matches a manual recomputation using JSON
    bom_copy = copy.deepcopy(bom)
    del bom_copy["manifest_hash"]
    del bom_copy["timestamp"]
    expected_hash = hashlib.sha256(
        json.dumps(bom_copy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert bom["manifest_hash"] == expected_hash
