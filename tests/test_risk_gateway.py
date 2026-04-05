import uuid
from unittest.mock import patch

from qwed_mcp.security import RiskBasedExecutionGateway


def test_unknown_tool_is_blocked_by_default():
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route("unknown_tool", {})

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["risk_level"] == "high"
    assert result["error_code"] == "QWED-MCP-RISK-001"


def test_execute_python_code_blocks_missing_code(monkeypatch):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "true")
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route("execute_python_code", {})

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-MCP-RISK-003"


def test_execute_python_code_requires_safe_verification(monkeypatch):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "true")
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route(
        "execute_python_code", {"code": "eval(input())"}
    )

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-MCP-RISK-005"
    assert "blocked python execution" in result["message"].lower()


def test_execute_python_code_returns_verified_allow_when_safe(monkeypatch):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "true")
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route(
        "execute_python_code", {"code": "print('safe')", "background": True}
    )

    assert result["verified"] is True
    assert result["status"] == "ALLOW_VERIFIED"
    assert result["risk_level"] == "high"
    assert result["normalized_arguments"]["background"] is True


def test_execute_python_code_blocks_when_verifier_raises(monkeypatch):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "true")
    gateway = RiskBasedExecutionGateway()

    with patch(
        "qwed_mcp.security.risk_gateway.verify_code_safety",
        side_effect=RuntimeError("boom"),
    ):
        result = gateway.evaluate_and_route(
            "execute_python_code", {"code": "print('safe')"}
        )

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-MCP-RISK-005"
    assert "verification error: boom" in result["message"].lower()


def test_execute_python_code_respects_admin_policy_after_verification(monkeypatch):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "false")
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route(
        "execute_python_code", {"code": "print('safe')"}
    )

    assert result["verified"] is False
    assert result["status"] == "BLOCKED_ADMIN_POLICY"
    assert result["error_code"] == "QWED-MCP-RISK-006"


def test_verification_status_requires_canonical_uuid():
    gateway = RiskBasedExecutionGateway()
    job_id = str(uuid.uuid4()).upper()

    result = gateway.evaluate_and_route(
        "verification_status", {"job_id": job_id}
    )

    assert result["verified"] is True
    assert result["status"] == "ALLOW_VERIFIED"
    assert result["normalized_arguments"]["job_id"] == job_id.lower()


def test_verification_status_blocks_missing_job_id():
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route("verification_status", {})

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-MCP-RISK-007"


def test_verification_status_blocks_invalid_uuid():
    gateway = RiskBasedExecutionGateway()

    result = gateway.evaluate_and_route(
        "verification_status", {"job_id": "not-a-uuid"}
    )

    assert result["verified"] is False
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "QWED-MCP-RISK-008"
