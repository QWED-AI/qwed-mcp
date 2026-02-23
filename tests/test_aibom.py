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
    
    # We test that the hash is actually present and valid hex
    bom = generator.generate_manifest("claude-3-opus", [], ["search"])
    
    assert len(bom["manifest_hash"]) == 64 # SHA256 length
    
    # Optional: verify hash generation logic manually
    import hashlib
    bom_copy = bom.copy()
    del bom_copy["manifest_hash"]
    expected_hash = hashlib.sha256(str(bom_copy).encode()).hexdigest()
    assert bom["manifest_hash"] == expected_hash
