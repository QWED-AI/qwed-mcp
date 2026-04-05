"""Verification-first governance gateway for MCP tool execution."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any, Dict

from qwed_mcp.engines.code_engine import verify_code_safety


class RiskBasedExecutionGateway:
    """Wrap MCP tool execution with QWED-aligned verification and policy checks."""

    _TOOL_POLICIES: Dict[str, Dict[str, Any]] = {
        "execute_python_code": {
            "risk_level": "high",
            "requires_verification": True,
        },
        "verification_status": {
            "risk_level": "low",
            "requires_verification": True,
        },
    }

    def evaluate_and_route(
        self, tool_name: str, arguments: dict[str, Any] | None
    ) -> Dict[str, Any]:
        """Verify a tool call and return a governance decision."""
        raw_arguments = arguments or {}
        policy = self._TOOL_POLICIES.get(tool_name)
        if policy is None:
            return self._blocked(
                tool_name=tool_name,
                risk_level="high",
                message=f"Unknown MCP tool '{tool_name}' is blocked by default.",
                arguments=raw_arguments,
                error_code="QWED-MCP-RISK-001",
            )

        if tool_name == "execute_python_code":
            return self._evaluate_python_execution(tool_name, raw_arguments, policy)
        if tool_name == "verification_status":
            return self._evaluate_status_lookup(tool_name, raw_arguments, policy)

        return self._blocked(
            tool_name=tool_name,
            risk_level=policy["risk_level"],
            message=f"Tool '{tool_name}' has no deterministic governance policy.",
            arguments=raw_arguments,
            error_code="QWED-MCP-RISK-002",
        )

    def _evaluate_python_execution(
        self, tool_name: str, arguments: dict[str, Any], policy: dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify python execution requests before dispatch."""
        code = arguments.get("code")
        if not isinstance(code, str) or not code.strip():
            return self._blocked(
                tool_name=tool_name,
                risk_level=policy["risk_level"],
                message="Missing required non-empty 'code' argument.",
                arguments=arguments,
                error_code="QWED-MCP-RISK-003",
            )

        background = arguments.get("background", False)
        if not isinstance(background, bool):
            return self._blocked(
                tool_name=tool_name,
                risk_level=policy["risk_level"],
                message="'background' must be a boolean when provided.",
                arguments=arguments,
                error_code="QWED-MCP-RISK-004",
            )

        normalized_arguments = {
            "code": code,
            "background": background,
        }
        verification_id = self._build_verification_id(tool_name, normalized_arguments)
        try:
            verification = verify_code_safety(code, "python")
        except Exception as exc:
            return self._blocked(
                tool_name=tool_name,
                risk_level=policy["risk_level"],
                message=f"QWED blocked python execution: verification error: {exc}",
                arguments=normalized_arguments,
                error_code="QWED-MCP-RISK-005",
                verification_id=verification_id,
            )
        if not verification.get("verified", False):
            issues = verification.get("issues", [])
            issue_text = "; ".join(issues) if issues else verification.get(
                "message", "Code safety verification failed."
            )
            return self._blocked(
                tool_name=tool_name,
                risk_level=policy["risk_level"],
                message=f"QWED blocked python execution: {issue_text}",
                arguments=normalized_arguments,
                error_code="QWED-MCP-RISK-005",
                verification_id=verification_id,
            )

        trusted_mode = (
            os.getenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "false").lower() == "true"
        )
        if not trusted_mode:
            return {
                "verified": False,
                "status": "BLOCKED_ADMIN_POLICY",
                "risk_level": policy["risk_level"],
                "verification_id": verification_id,
                "normalized_arguments": normalized_arguments,
                "message": (
                    "Python execution was verified, but server policy keeps code "
                    "execution disabled until QWED_MCP_TRUSTED_CODE_EXECUTION=true."
                ),
                "error_code": "QWED-MCP-RISK-006",
            }

        return {
            "verified": True,
            "status": "ALLOW_VERIFIED",
            "risk_level": policy["risk_level"],
            "verification_id": verification_id,
            "normalized_arguments": normalized_arguments,
            "message": "Python execution request passed deterministic verification.",
        }

    def _evaluate_status_lookup(
        self, tool_name: str, arguments: dict[str, Any], policy: dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate non-executing job status lookups deterministically."""
        job_id = arguments.get("job_id")
        if not isinstance(job_id, str) or not job_id.strip():
            return self._blocked(
                tool_name=tool_name,
                risk_level=policy["risk_level"],
                message="Missing required non-empty 'job_id' argument.",
                arguments=arguments,
                error_code="QWED-MCP-RISK-007",
            )

        try:
            canonical_job_id = str(uuid.UUID(job_id.strip()))
        except ValueError:
            return self._blocked(
                tool_name=tool_name,
                risk_level=policy["risk_level"],
                message="Invalid job_id format. Expected a canonical UUID.",
                arguments=arguments,
                error_code="QWED-MCP-RISK-008",
            )

        normalized_arguments = {"job_id": canonical_job_id}
        return {
            "verified": True,
            "status": "ALLOW_VERIFIED",
            "risk_level": policy["risk_level"],
            "verification_id": self._build_verification_id(
                tool_name, normalized_arguments
            ),
            "normalized_arguments": normalized_arguments,
            "message": "Verification status lookup passed deterministic validation.",
        }

    @staticmethod
    def _build_verification_id(tool_name: str, arguments: dict[str, Any]) -> str:
        """Create a deterministic verification fingerprint for a tool request."""
        payload = json.dumps(
            {"tool_name": tool_name, "arguments": arguments},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _blocked(
        self,
        *,
        tool_name: str,
        risk_level: str,
        message: str,
        arguments: dict[str, Any],
        error_code: str,
        verification_id: str | None = None,
    ) -> Dict[str, Any]:
        """Return a consistent blocked decision payload."""
        return {
            "verified": False,
            "status": "BLOCKED",
            "risk_level": risk_level,
            "verification_id": verification_id
            or self._build_verification_id(tool_name, arguments),
            "normalized_arguments": arguments,
            "message": message,
            "error_code": error_code,
        }
