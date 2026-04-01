"""
Skill Provenance Guard — MCP Skill Supply Chain Verification.

Protects against skill marketplace poisoning attacks where malicious
agents upload trojanized "Skills" to registries (e.g., ClawdHub/Moltbot),
artificially inflate download counts using bots, and trick developers
into loading and executing unvetted code within their agentic pipelines.

This guard enforces:
- Registry allowlisting (blocks known unvetted sources)
- Digest format requirement (algorithm:hex_digest presence check)
- Source URL validation against trusted domains
- Download count anomaly detection (bot inflation signals)
"""

import math
import re
from typing import Any, Dict, FrozenSet, List, Optional, Set
from urllib.parse import urlparse


# Registries known to have insufficient vetting processes
_UNTRUSTED_REGISTRIES: FrozenSet[str] = frozenset({
    "clawdhub.com",
    "moltbot.io",
    "skillhub.ai",
    "agentstore.dev",
    "llm-tools.net",
})

# Trusted domains for skill source URLs
_TRUSTED_DOMAINS: FrozenSet[str] = frozenset({
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "pypi.org",
    "npmjs.com",
    "qwedai.com",
})

# Suspicious patterns in skill code/manifest
_MALICIOUS_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bsubprocess\.(call|run|Popen)\s*\("),
    re.compile(r"\b(credentials|api[_-]?key|secret[_-]?key)\b", re.IGNORECASE),
    re.compile(r"\bopen\s*\(.*(\/etc\/|\/root\/|\.ssh\/|\.aws\/)", re.IGNORECASE),
    re.compile(r"\brequests\.(get|post)\s*\(.*\b(pastebin|ngrok|burp)", re.IGNORECASE),
]


def _scan_value_recursive(
    path: str, value: Any, findings: List[str]
) -> None:
    """Recursively scan manifest values for malicious patterns."""
    if isinstance(value, str):
        for pattern in _MALICIOUS_PATTERNS:
            if pattern.search(value):
                findings.append(
                    f"Suspicious pattern '{pattern.pattern}' "
                    f"in manifest field '{path}'"
                )
        return
    if isinstance(value, dict):
        for child_key, child_value in sorted(
            value.items(), key=lambda item: str(item[0])
        ):
            _scan_value_recursive(f"{path}.{child_key}", child_value, findings)
        return
    if isinstance(value, (list, tuple)):
        for idx, child_value in enumerate(value):
            _scan_value_recursive(f"{path}[{idx}]", child_value, findings)


class SkillProvenanceGuard:
    """
    Deterministic skill provenance verification for MCP-loaded tools.

    Validates skill manifests before allowing dynamic tool loading,
    blocking known attack vectors from poisoned skill marketplaces.

    Usage:
        guard = SkillProvenanceGuard()
        result = guard.verify_skill(manifest={
            "name": "my-skill",
            "version": "1.0.0",
            "source_url": "https://github.com/org/skill",
            "registry": "github.com",
            "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "download_count": 150,
        })
        if not result["verified"]:
            print("BLOCKED:", result["message"])
    """

    # Thresholds for anomaly detection
    MIN_DOWNLOAD_COUNT = 10       # Below this → likely bot manipulation
    SUSPICIOUSLY_ROUND = 1000     # Counts divisible by this → bot signals

    def __init__(
        self,
        trusted_registries: Optional[Set[str]] = None,
        trusted_domains: Optional[Set[str]] = None,
        require_digest: bool = True,
    ):
        """
        Args:
            trusted_registries: If provided, enforces a strict allowlist of registry domains.
            trusted_domains: Additional source URL domains to trust.
            require_digest: Whether to enforce digest presence.
        """
        self.blocked_registries = set(_UNTRUSTED_REGISTRIES)
        self.trusted_domains = set(_TRUSTED_DOMAINS)
        self.trusted_registries = set()
        self.enforce_registry_allowlist = False
        
        if trusted_registries is not None:
            self.enforce_registry_allowlist = True
            self.trusted_registries = {
                registry.lower().strip().rstrip(".")
                for registry in trusted_registries
                if isinstance(registry, str) and registry.strip()
            }
            
        if trusted_domains:
            self.trusted_domains |= {
                domain.lower().strip().rstrip(".")
                for domain in trusted_domains
                if isinstance(domain, str) and domain.strip()
            }
        self.require_digest = require_digest

    def _validate_registry(self, manifest: Dict[str, Any]) -> List[str]:
        """Check if the skill comes from a blocked registry."""
        findings: List[str] = []
        registry = manifest.get("registry")
        if not isinstance(registry, str):
            findings.append(f"Invalid registry type: {type(registry).__name__}")
            return findings
            
        registry = registry.lower().strip().rstrip(".")
        if not registry:
            findings.append("Missing registry field in manifest")
            return findings
            
        if self.enforce_registry_allowlist:
            if registry not in self.trusted_registries:
                findings.append(
                    f"Skill loaded from untrusted registry: {registry} "
                    f"(not in explicit allowlist)"
                )
            return findings
            
        for blocked in sorted(self.blocked_registries):
            if blocked in registry:
                findings.append(
                    f"Skill loaded from untrusted registry: {registry} "
                    f"(blocked: {blocked})"
                )
        return findings

    def _validate_source_url(self, manifest: Dict[str, Any]) -> List[str]:
        """Validate source URL against trusted domain allowlist."""
        findings: List[str] = []
        source_url = manifest.get("source_url")
        if not isinstance(source_url, str):
            findings.append(f"Invalid source_url type: {type(source_url).__name__}")
            return findings
            
        source_url = source_url.strip()
        if not source_url:
            findings.append("Missing source_url in manifest")
            return findings

        try:
            parsed = urlparse(source_url)
            domain = parsed.hostname or ""
        except Exception:
            findings.append(f"Invalid source URL: {source_url}")
            return findings

        domain = domain.lower().rstrip('.')
        if not any(
            domain == trusted.lower()
            or domain.endswith(f".{trusted.lower()}")
            for trusted in self.trusted_domains
        ):
            findings.append(
                f"Source URL domain '{domain}' is not in trusted list"
            )

        if parsed.scheme not in ("https",):
            findings.append(
                f"Source URL uses insecure scheme: {parsed.scheme}"
            )

        return findings

    def _validate_digest(self, manifest: Dict[str, Any]) -> List[str]:
        """Verify digest is present and well-formed."""
        findings: List[str] = []
        digest_val = manifest.get("digest")

        if digest_val is None:
            if self.require_digest:
                findings.append(
                    "Missing digest — "
                    "unsigned skills are not allowed"
                )
            return findings

        if not isinstance(digest_val, str):
            findings.append(f"Invalid digest type: {type(digest_val).__name__}")
            return findings
            
        digest_val = digest_val.strip()
        if not digest_val:
            if self.require_digest:
                findings.append(
                    "Missing digest — "
                    "unsigned skills are not allowed"
                )
            return findings

        # Expected format: "algorithm:hex_digest"
        parts = digest_val.split(":", 1)
        if len(parts) != 2:
            findings.append(
                f"Malformed digest format: {digest_val} "
                f"(expected 'algorithm:hex_digest')"
            )
            return findings

        algo, digest = parts
        valid_algos = {"sha256", "sha384", "sha512"}
        expected_lengths = {"sha256": 64, "sha384": 96, "sha512": 128}
        if algo.lower() not in valid_algos:
            findings.append(
                f"Unsupported digest algorithm: {algo} "
                f"(accepted: {', '.join(sorted(valid_algos))})"
            )
        elif not re.match(r"^[0-9a-fA-F]+$", digest):
            findings.append(
                f"Invalid digest (not hex): {digest[:32]}..."
            )
        elif len(digest) != expected_lengths[algo.lower()]:
            findings.append(
                f"Invalid digest length for {algo}: expected "
                f"{expected_lengths[algo.lower()]} hex chars, got {len(digest)}"
            )

        return findings

    def _detect_download_anomalies(
        self, manifest: Dict[str, Any]
    ) -> List[str]:
        """Detect bot-inflated download counts."""
        findings: List[str] = []
        download_count = manifest.get("download_count")

        if download_count is None:
            return findings

        if isinstance(download_count, bool) or not isinstance(download_count, (int, float)):
            findings.append(
                f"Invalid download_count type: {type(download_count).__name__}"
            )
            return findings

        if isinstance(download_count, float):
            if not math.isfinite(download_count):
                findings.append(f"Invalid download_count (non-finite float): {download_count}")
                return findings
            if not download_count.is_integer():
                findings.append(f"Invalid download_count (non-integer float): {download_count}")
                return findings

        count = int(download_count)
        if count < self.MIN_DOWNLOAD_COUNT:
            findings.append(
                f"Suspiciously low download count ({count}) — "
                f"possible newly planted malicious skill"
            )

        if count > 0 and count % self.SUSPICIOUSLY_ROUND == 0:
            findings.append(
                f"Download count ({count}) is suspiciously round — "
                f"possible bot inflation"
            )

        return findings

    def _scan_manifest_content(self, manifest: Dict[str, Any]) -> List[str]:
        """Scan manifest fields for embedded malicious patterns."""
        findings: List[str] = []
        
        # Exclude metadata fields prone to false positives
        exclude_fields = {"name", "description", "source_url", "registry", "author", "license", "version", "digest"}
        
        # Scan string values for code injection attempts
        for key, value in sorted(manifest.items(), key=lambda item: str(item[0])):
            if key in exclude_fields:
                continue
            _scan_value_recursive(str(key), value, findings)
        return findings

    def verify_skill(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a skill manifest before allowing it to be loaded.

        Args:
            manifest: Skill manifest dict with keys:
                - name (str): Skill name
                - version (str): Skill version
                - source_url (str): Source repository URL
                - registry (str): Registry domain
                - digest (str): Cryptographic digest
                - download_count (int): Number of downloads

        Returns:
            Dict with keys:
                - verified (bool): True if skill is safe to load.
                - status (str): "TRUSTED" or "BLOCKED".
                - findings (list): All security findings.
                - risk_level (str): "none", "low", "medium", "high".
                - message (str): Human-readable summary.
        """
        all_findings: List[str] = []
        raw_name = manifest.get("name")
        skill_name = (
            raw_name.strip()
            if isinstance(raw_name, str) and raw_name.strip()
            else "unknown"
        )

        # Required field check
        if not isinstance(raw_name, str) or not raw_name.strip():
            all_findings.append("Missing required field: name")
            
        raw_version = manifest.get("version")
        if not isinstance(raw_version, str) or not raw_version.strip():
            all_findings.append("Missing required field: version")

        # Run all validation checks
        all_findings.extend(self._validate_registry(manifest))
        all_findings.extend(self._validate_source_url(manifest))
        all_findings.extend(self._validate_digest(manifest))
        all_findings.extend(self._detect_download_anomalies(manifest))
        all_findings.extend(self._scan_manifest_content(manifest))

        if not all_findings:
            return {
                "verified": True,
                "status": "TRUSTED",
                "skill_name": skill_name,
                "risk_level": "none",
                "findings": [],
                "message": (
                    f"Skill '{skill_name}' passed all provenance checks."
                ),
            }

        # Classify risk
        high_risk_keywords = {
            "untrusted registry", "Suspicious pattern",
            "Missing digest", "Malformed digest",
            "Invalid digest", "Unsupported digest algorithm"
        }
        has_high_risk = any(
            any(kw in f for kw in high_risk_keywords)
            for f in all_findings
        )
        risk_level = "high" if has_high_risk else "medium"

        return {
            "verified": False,
            "status": "BLOCKED",
            "skill_name": skill_name,
            "risk_level": risk_level,
            "findings": all_findings,
            "message": (
                f"BLOCKED: Skill '{skill_name}' failed {len(all_findings)} "
                f"provenance check(s) (risk: {risk_level}). "
                f"Loading untrusted skills is a known supply chain attack vector."
            ),
        }
