import os
from unittest.mock import MagicMock, patch
import pytest

from nhi.remediation.handlers.policy import handle_policy_remediation
from nhi.remediation.handlers.credential import handle_credential_remediation
from nhi.remediation.dispatch import dispatch_remediation


# ==========================================
# 1. Tests for Policy Handler (policy.py)
# ==========================================

class TestPolicyRemediationHandler:
    
    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        monkeypatch.setenv("NHI_BOUNDARY_POLICY_ARN", "arn:aws:iam::123456789012:policy/nhi-permissions-boundary")

    def test_policy_dry_run_user(self):
        finding = {
            "RuleID": "IAM_01",
            "IdentityType": "User",
            "IdentityName": "test-runner-user"
        }
        result = handle_policy_remediation(finding, dry_run=True)
        assert result is True

    def test_policy_dry_run_role(self):
        finding = {
            "RuleID": "IAM_04",
            "IdentityType": "Role",
            "IdentityName": "test-runner-role"
        }
        result = handle_policy_remediation(finding, dry_run=True)
        assert result is True

    @patch("nhi.remediation.handlers.policy.set_user_permissions_boundary")
    def test_policy_live_remediation_user_success(self, mock_set_user_boundary):
        mock_set_user_boundary.return_value = True
        finding = {
            "RuleID": "IAM_01",
            "IdentityType": "User",
            "IdentityName": "test-runner-user"
        }
        result = handle_policy_remediation(finding, dry_run=False)
        assert result is True
        mock_set_user_boundary.assert_called_once_with(
            "test-runner-user", 
            "arn:aws:iam::123456789012:policy/nhi-permissions-boundary"
        )

    @patch("nhi.remediation.handlers.policy.set_role_permissions_boundary")
    def test_policy_live_remediation_role_success(self, mock_set_role_boundary):
        mock_set_role_boundary.return_value = True
        finding = {
            "RuleID": "IAM_04",
            "IdentityType": "Role",
            "IdentityName": "test-runner-role"
        }
        result = handle_policy_remediation(finding, dry_run=False)
        assert result is True
        mock_set_role_boundary.assert_called_once_with(
            "test-runner-role", 
            "arn:aws:iam::123456789012:policy/nhi-permissions-boundary"
        )

    def test_policy_missing_boundary_arn(self, monkeypatch):
        monkeypatch.delenv("NHI_BOUNDARY_POLICY_ARN", raising=False)
        finding = {
            "RuleID": "IAM_01",
            "IdentityType": "User",
            "IdentityName": "test-user"
        }
        result = handle_policy_remediation(finding, dry_run=False)
        assert result is False

    def test_policy_group_fallback(self):
        finding = {
            "RuleID": "IAM_01",
            "IdentityType": "Group",
            "IdentityName": "test-admin-group"
        }
        # Groups cannot receive boundaries
        result = handle_policy_remediation(finding, dry_run=False)
        assert result is False

    def test_policy_missing_identity_name(self):
        finding = {
            "RuleID": "IAM_01",
            "IdentityType": "User"
        }
        result = handle_policy_remediation(finding, dry_run=False)
        assert result is False


# ==========================================
# 2. Tests for Credential Handler (credential.py)
# ==========================================

class TestCredentialRemediationHandler:

    def test_credential_dry_run(self):
        finding = {
            "RuleID": "IAM_11",
            "IdentityName": "test-user",
            "TargetID": "AKIA123456789EXAMPLE"
        }
        result = handle_credential_remediation(finding, dry_run=True)
        assert result is True

    @patch("nhi.remediation.handlers.credential.update_access_key")
    def test_credential_live_remediation_success(self, mock_update_key):
        mock_update_key.return_value = {"HTTPStatusCode": 200}
        finding = {
            "RuleID": "IAM_11",
            "IdentityName": "test-user",
            "TargetID": "AKIA123456789EXAMPLE"
        }
        result = handle_credential_remediation(finding, dry_run=False)
        assert result is True
        mock_update_key.assert_called_once_with("test-user", "AKIA123456789EXAMPLE", "Inactive")

    @patch("nhi.remediation.handlers.credential.update_access_key")
    def test_credential_live_remediation_failure(self, mock_update_key):
        mock_update_key.return_value = None
        finding = {
            "RuleID": "IAM_12",
            "IdentityName": "test-user",
            "TargetID": "AKIA123456789EXAMPLE"
        }
        result = handle_credential_remediation(finding, dry_run=False)
        assert result is False

    def test_credential_missing_fields(self):
        finding = {"RuleID": "IAM_11", "IdentityName": "test-user"}
        result = handle_credential_remediation(finding, dry_run=False)
        assert result is False


# ==========================================
# 3. Tests for Dispatch Pipeline (dispatch.py)
# ==========================================

class TestDispatchRemediation:

    @patch("nhi.remediation.dispatch.load_ignore_config")
    @patch("nhi.remediation.dispatch.is_ignored")
    @patch("nhi.remediation.dispatch.HANDLER_MAP")
    def test_dispatch_mixed_findings(self, mock_handler_map, mock_is_ignored, mock_load_config):
        mock_load_config.return_value = {}
        
        # Finding 1: Policy (Remediated)
        # Finding 2: Key (Skipped via exemption)
        # Finding 3: Unknown rule (Failed)
        findings = [
            {"RuleID": "IAM_01", "IdentityType": "User", "IdentityName": "user-1"},
            {"RuleID": "IAM_11", "IdentityName": "user-2", "TargetID": "AKIA1"},
            {"RuleID": "IAM_99_UNKNOWN", "IdentityName": "user-3"}
        ]

        def mock_ignored_side_effect(finding, exemptions):
            return finding.get("RuleID") == "IAM_11"

        mock_is_ignored.side_effect = mock_ignored_side_effect

        mock_policy_handler = MagicMock(return_value=True)
        mock_handler_map.get.side_effect = lambda rule: mock_policy_handler if rule == "IAM_01" else None

        # 1. Assert DRY-RUN returns 'would_remediate'
        dry_run_stats = dispatch_remediation(findings, dry_run=True)
        assert dry_run_stats == {
            "total": 3,
            "would_remediate": 1,
            "manual_review_required": 0,
            "skipped": 1,
            "failed": 1,
        }

        # 2. Assert LIVE execution returns 'remediated'
        live_stats = dispatch_remediation(findings, dry_run=False)
        assert live_stats == {
            "total": 3,
            "remediated": 1,
            "manual_review_required": 0,
            "skipped": 1,
            "failed": 1,
        }