"""
Tests for SkillProvenanceGuard — Skill Supply Chain Verification.
"""

from qwed_mcp.security.provenance import SkillProvenanceGuard


def _make_manifest(**overrides):
    """Helper to create a valid manifest with optional overrides."""
    base = {
        "name": "test-skill",
        "version": "1.0.0",
        "source_url": "https://github.com/qwed-ai/test-skill",
        "registry": "github.com",
        "signature": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "download_count": 150,
    }
    base.update(overrides)
    return base


class TestSkillProvenanceGuard:
    """Tests for skill manifest provenance verification."""

    # --- Clean manifests ---

    def test_valid_manifest_passes(self):
        """A fully valid manifest should pass all checks."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest())

        assert result["verified"] is True
        assert result["status"] == "TRUSTED"
        assert result["risk_level"] == "none"
        assert result["findings"] == []
        assert "passed" in result["message"]

    def test_valid_manifest_with_custom_trusted_domain(self):
        """Custom trusted domains should be accepted."""
        guard = SkillProvenanceGuard(trusted_domains={"internal.corp"})
        result = guard.verify_skill(
            _make_manifest(source_url="https://internal.corp/skill")
        )

        assert result["verified"] is True

    # --- Registry validation ---

    def test_blocks_untrusted_registry(self):
        """Skills from untrusted registries should be blocked."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(registry="clawdhub.com")
        )

        assert result["verified"] is False
        assert result["risk_level"] == "high"
        assert any("untrusted registry" in f for f in result["findings"])

    def test_blocks_multiple_untrusted_registries(self):
        """Should block all known untrusted registries."""
        guard = SkillProvenanceGuard()
        for reg in ["moltbot.io", "skillhub.ai", "agentstore.dev"]:
            result = guard.verify_skill(_make_manifest(registry=reg))
            assert result["verified"] is False
            assert any("untrusted" in f for f in result["findings"])

    def test_missing_registry_flagged(self):
        """Missing registry field should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(registry=""))

        assert result["verified"] is False
        assert any("Missing registry" in f for f in result["findings"])

    def test_custom_trusted_registry_unblocks(self):
        """Explicitly trusting a blocked registry should unblock it."""
        guard = SkillProvenanceGuard(
            trusted_registries={"clawdhub.com"}
        )
        result = guard.verify_skill(
            _make_manifest(registry="clawdhub.com")
        )

        # Should not be blocked by registry check (may still fail other checks)
        assert not any("untrusted registry" in f for f in result["findings"])

    # --- Source URL validation ---

    def test_blocks_untrusted_source_url(self):
        """Source URLs from non-trusted domains should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(source_url="https://evil-skills.com/backdoor")
        )

        assert result["verified"] is False
        assert any("not in trusted list" in f for f in result["findings"])

    def test_blocks_http_source_url(self):
        """Non-HTTPS source URLs should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(source_url="http://github.com/org/skill")
        )

        assert result["verified"] is False
        assert any("insecure scheme" in f for f in result["findings"])

    def test_missing_source_url_flagged(self):
        """Missing source_url should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(source_url=""))

        assert result["verified"] is False
        assert any("Missing source_url" in f for f in result["findings"])

    # --- Signature validation ---

    def test_missing_signature_blocked(self):
        """Missing signature should be blocked when required."""
        guard = SkillProvenanceGuard(require_signature=True)
        result = guard.verify_skill(_make_manifest(signature=""))

        assert result["verified"] is False
        assert result["risk_level"] == "high"
        assert any("unsigned" in f.lower() for f in result["findings"])

    def test_signature_not_required(self):
        """Should pass when signature is not required."""
        guard = SkillProvenanceGuard(require_signature=False)
        result = guard.verify_skill(_make_manifest(signature=""))

        assert result["verified"] is True

    def test_malformed_signature_flagged(self):
        """Malformed signatures should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(signature="not-a-valid-signature")
        )

        assert result["verified"] is False
        assert any("Malformed signature" in f for f in result["findings"])

    def test_unsupported_algorithm_flagged(self):
        """Unsupported hash algorithms should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(signature="md5:abc123")
        )

        assert result["verified"] is False
        assert any("Unsupported signature algorithm" in f for f in result["findings"])

    def test_invalid_hex_digest_flagged(self):
        """Non-hex digest values should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(signature="sha256:not-hex-data!")
        )

        assert result["verified"] is False
        assert any("not hex" in f for f in result["findings"])

    def test_valid_sha384_accepted(self):
        """SHA-384 signatures should be accepted."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(signature="sha384:" + "ab" * 48)
        )

        assert result["verified"] is True

    # --- Download anomaly detection ---

    def test_low_download_count_flagged(self):
        """Very low download counts suggest freshly planted malware."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(download_count=3))

        assert result["verified"] is False
        assert any("low download count" in f.lower() for f in result["findings"])

    def test_round_download_count_flagged(self):
        """Suspiciously round counts indicate bot inflation."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(download_count=5000))

        assert result["verified"] is False
        assert any("bot inflation" in f for f in result["findings"])

    def test_normal_download_count_passes(self):
        """Normal download counts should not trigger anomaly detection."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(download_count=247))

        assert result["verified"] is True

    def test_missing_download_count_passes(self):
        """Missing download count is not an error (optional field)."""
        guard = SkillProvenanceGuard()
        manifest = _make_manifest()
        del manifest["download_count"]
        result = guard.verify_skill(manifest)

        assert result["verified"] is True

    # --- Manifest content scanning ---

    def test_detects_eval_in_manifest(self):
        """Should detect code injection patterns in manifest fields."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(description="eval(compile('malicious', '', 'exec'))")
        )

        assert result["verified"] is False
        assert any("Suspicious pattern" in f for f in result["findings"])

    def test_detects_credential_exfil_in_manifest(self):
        """Should detect credential harvesting patterns."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(install_hook="open('/root/.ssh/id_rsa').read()")
        )

        assert result["verified"] is False
        assert any("Suspicious pattern" in f for f in result["findings"])

    # --- Required fields ---

    def test_missing_name_flagged(self):
        """Missing name should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(name=""))

        assert result["verified"] is False
        assert any("Missing required field: name" in f for f in result["findings"])

    def test_missing_version_flagged(self):
        """Missing version should be flagged."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(version=""))

        assert result["verified"] is False
        assert any("Missing required field: version" in f for f in result["findings"])

    # --- Message accuracy ---

    def test_message_includes_finding_count(self):
        """Message should include the number of findings."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(
            _make_manifest(registry="clawdhub.com", signature="")
        )

        assert result["verified"] is False
        assert "failed" in result["message"]
        assert "provenance check" in result["message"]

    def test_skill_name_in_result(self):
        """Result should include the skill name."""
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(_make_manifest(name="my-cool-skill"))

        assert result["skill_name"] == "my-cool-skill"


def test_security_package_exports():
    """Verify that SkillProvenanceGuard is importable from the package."""
    from qwed_mcp.security import SkillProvenanceGuard as Guard
    assert callable(Guard)
