"""
Skill Provenance Guard — MCP Skill Supply Chain Verification.

Protects against skill marketplace poisoning attacks where malicious
agents upload trojanized "Skills" to registries (e.g., ClawdHub/Moltbot),
artificially inflate download counts using bots, and trick developers
into loading and executing unvetted code within their agentic pipelines.

This guard enforces:
- Registry allowlisting: a registry must be listed exactly; known unvetted
  registries and their subdomains are refused outright
- Digest format, and the digest against the skill's bytes when the caller
  supplies them (``content``); without them the result says the digest was
  not checked against content
- Source URL validation against trusted domains
- A scan of manifest fields, including the description and source URL, for
  code-execution patterns

Download counts come from the registry being audited, so they are reported
as advisories and never decide the result (#47).

The registry, source URL and digest are claims the manifest makes about
itself. The guard checks those claims against its lists and, when given the
skill's bytes, the digest against them; it does not establish where the
manifest came from.
"""

import hashlib
import hmac
import math
import re
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse


# Registries known to have insufficient vetting processes
_UNTRUSTED_REGISTRIES: FrozenSet[str] = frozenset({
    "clawdhub.com",
    "moltbot.io",
    "skillhub.ai",
    "agentstore.dev",
    "llm-tools.net",
})

# Trusted domains for skill source URLs. No QWED-owned domain is listed:
# QWED's sources live on github.com, and a domain that lapses can be
# registered by anyone, so it must not stay a trust anchor (#71).
_TRUSTED_DOMAINS: FrozenSet[str] = frozenset({
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "pypi.org",
    "npmjs.com",
})

# Code-execution patterns: scanned in every manifest field, free text and the
# source URL included (#58).
_CODE_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bsubprocess\.(call|run|Popen)\s*\("),
    re.compile(r"\bopen\s*\(.*(\/etc\/|\/root\/|\.ssh\/|\.aws\/)", re.IGNORECASE),
    re.compile(r"\brequests\.(get|post)\s*\(.*\b(pastebin|ngrok|burp)", re.IGNORECASE),
]

# Secret-name keywords: not scanned in name, description and the other
# identity fields, where a skill may legitimately mention them.
_KEYWORD_PATTERNS = [
    re.compile(r"\b(credentials|api[_-]?key|secret[_-]?key)\b", re.IGNORECASE),
]

_MALICIOUS_PATTERNS = _CODE_PATTERNS + _KEYWORD_PATTERNS

_DIGEST_ALGORITHMS = {"sha256": 64, "sha384": 96, "sha512": 128}


def _scan_value_recursive(
    path: str, value: Any, findings: List[str], patterns=None
) -> None:
    """Recursively scan manifest values for malicious patterns."""
    patterns = _MALICIOUS_PATTERNS if patterns is None else patterns
    if isinstance(value, str):
        for pattern in patterns:
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
            _scan_value_recursive(
                f"{path}.{child_key}", child_value, findings, patterns
            )
        return
    if isinstance(value, (list, tuple)):
        for idx, child_value in enumerate(value):
            _scan_value_recursive(f"{path}[{idx}]", child_value, findings, patterns)


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
            trusted_registries: The registries a skill may come from, matched
                exactly. Defaults to the trusted source domains (github.com,
                gitlab.com, bitbucket.org, pypi.org, npmjs.com); an unlisted
                registry is refused (#58).
            trusted_domains: Additional source URL domains to trust.
            require_digest: Whether to enforce digest presence.
        """
        self.blocked_registries = set(_UNTRUSTED_REGISTRIES)
        self.trusted_domains = set(_TRUSTED_DOMAINS)
        if trusted_registries is None:
            trusted_registries = _TRUSTED_DOMAINS
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
            
        # A registry the caller lists is trusted, even a known-unvetted one.
        if registry in self.trusted_registries:
            return findings

        # Exact domain or subdomain, never a substring (#18).
        for blocked in sorted(self.blocked_registries):
            if registry == blocked or registry.endswith(f".{blocked}"):
                findings.append(
                    f"Skill loaded from untrusted registry: {registry} "
                    f"(blocked: {blocked})"
                )
                return findings

        findings.append(
            f"Skill loaded from untrusted registry: {registry} "
            f"(not in the registry allowlist)"
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

    def _validate_digest(
        self, manifest: Dict[str, Any], content: Optional[bytes] = None
    ) -> Tuple[List[str], bool]:
        """Verify the digest is present and well-formed, and when ``content``
        is given, that it is the digest of those bytes (#30).

        Returns the findings and whether a comparison with ``content`` was
        made and matched.
        """
        findings: List[str] = []
        digest_val = manifest.get("digest")

        if digest_val is None:
            if self.require_digest:
                findings.append(
                    "Missing digest — "
                    "unsigned skills are not allowed"
                )
            return findings, False

        if not isinstance(digest_val, str):
            findings.append(f"Invalid digest type: {type(digest_val).__name__}")
            return findings, False
            
        digest_val = digest_val.strip()
        if not digest_val:
            if self.require_digest:
                findings.append(
                    "Missing digest — "
                    "unsigned skills are not allowed"
                )
            return findings, False

        # Expected format: "algorithm:hex_digest"
        parts = digest_val.split(":", 1)
        if len(parts) != 2:
            findings.append(
                f"Malformed digest format: {digest_val} "
                f"(expected 'algorithm:hex_digest')"
            )
            return findings, False

        algo, digest = parts
        algo = algo.lower()
        if algo not in _DIGEST_ALGORITHMS:
            findings.append(
                f"Unsupported digest algorithm: {algo} "
                f"(accepted: {', '.join(sorted(_DIGEST_ALGORITHMS))})"
            )
        elif not re.match(r"^[0-9a-fA-F]+$", digest):
            findings.append(
                f"Invalid digest (not hex): {digest[:32]}..."
            )
        elif len(digest) != _DIGEST_ALGORITHMS[algo]:
            findings.append(
                f"Invalid digest length for {algo}: expected "
                f"{_DIGEST_ALGORITHMS[algo]} hex chars, got {len(digest)}"
            )
        elif content is not None:
            actual = hashlib.new(algo, content).hexdigest()
            if hmac.compare_digest(actual, digest.lower()):
                return findings, True
            findings.append(
                "Digest mismatch: the skill content does not match the "
                "attested digest"
            )

        return findings, False

    def _detect_download_anomalies(
        self, manifest: Dict[str, Any]
    ) -> List[str]:
        """Advisory notes on the download count. The count comes from the
        registry being audited, so these never decide the result (#47)."""
        findings: List[str] = []
        download_count = manifest.get("download_count")

        if download_count is None:
            findings.append("No download_count in the manifest (not used as a signal)")
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
        
        # Identity and free-text fields are scanned for code-execution
        # patterns only; secret-name keywords are legitimate there (#58).
        text_fields = {"name", "description", "source_url", "registry", "author", "license", "version", "digest"}

        for key, value in sorted(manifest.items(), key=lambda item: str(item[0])):
            patterns = _CODE_PATTERNS if key in text_fields else _MALICIOUS_PATTERNS
            _scan_value_recursive(str(key), value, findings, patterns)
        return findings

    def verify_skill(
        self, manifest: Dict[str, Any], content: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Verify a skill manifest before allowing it to be loaded.

        Args:
            content: The skill's bytes. When given, the manifest digest must
                be their digest; when omitted, the digest is checked for form
                only and the result says so (``digest_verified`` is False and
                the status is ``TRUSTED_DIGEST_UNVERIFIED``).
            manifest: Skill manifest dict with keys:
                - name (str): Skill name
                - version (str): Skill version
                - source_url (str): Source repository URL
                - registry (str): Registry domain
                - digest (str): Cryptographic digest
                - download_count (int): Number of downloads

        Returns:
            Dict with keys:
                - verified (bool): True if no provenance check failed.
                - status (str): "TRUSTED" (digest checked against content),
                  "TRUSTED_DIGEST_UNVERIFIED" (no content given) or "BLOCKED".
                - digest_verified (bool): the digest matched ``content``.
                - advisories (list): notes that do not decide the result.
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
        digest_findings, digest_verified = self._validate_digest(manifest, content)
        all_findings.extend(digest_findings)
        all_findings.extend(self._scan_manifest_content(manifest))
        advisories = self._detect_download_anomalies(manifest)

        if not all_findings:
            if digest_verified:
                status = "TRUSTED"
                message = f"Skill '{skill_name}' passed all provenance checks."
            else:
                status = "TRUSTED_DIGEST_UNVERIFIED"
                reason = (
                    "no skill content was supplied to compare it with"
                    if content is None
                    else "the manifest has no digest to compare the content with"
                )
                message = (
                    f"Skill '{skill_name}' passed the provenance checks, but its "
                    f"digest was not checked against content: {reason}."
                )
            return {
                "verified": True,
                "status": status,
                "digest_verified": digest_verified,
                "skill_name": skill_name,
                "risk_level": "none",
                "findings": [],
                "advisories": advisories,
                "message": message,
            }

        # Classify risk
        high_risk_keywords = {
            "untrusted registry", "Suspicious pattern",
            "Missing digest", "Malformed digest",
            "Invalid digest", "Unsupported digest algorithm", "Digest mismatch"
        }
        has_high_risk = any(
            any(kw in f for kw in high_risk_keywords)
            for f in all_findings
        )
        risk_level = "high" if has_high_risk else "medium"

        return {
            "verified": False,
            "status": "BLOCKED",
            "digest_verified": False,
            "skill_name": skill_name,
            "risk_level": risk_level,
            "findings": all_findings,
            "advisories": advisories,
            "message": (
                f"BLOCKED: Skill '{skill_name}' failed {len(all_findings)} "
                f"provenance check(s) (risk: {risk_level}). "
                f"Loading untrusted skills is a known supply chain attack vector."
            ),
        }
