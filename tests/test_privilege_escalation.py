import unittest
from nhi.risk.helpers import (
    classify_resources as classify,
    analyze_resources as analyze,
)
from nhi.risk.rules.privilege_escalation import analyze_policy_for_set_policy_version


class TestClassifyResources(unittest.TestCase):
    def test_bare_wildcard_is_unconstrained(self):
        self.assertEqual(classify("*"), "UNCONSTRAINED")

    def test_fully_wildcarded_arn_is_unconstrained(self):
        self.assertEqual(classify("arn:aws:*:*:*:*"), "UNCONSTRAINED")

    def test_iam_identity_name_wildcard_is_unconstrained(self):
        cases = [
            "arn:aws:iam::123456789012:role/*",
            "arn:aws:iam::123456789012:policy/*",
            "arn:aws:iam::123456789012:user/*",
            "arn:aws:iam::123456789012:group/*",
        ]
        for resource in cases:
            with self.subTest(resource=resource):
                self.assertEqual(classify(resource), "UNCONSTRAINED")

    def test_iam_specific_named_resource_is_specific(self):
        self.assertEqual(
            classify("arn:aws:iam::123456789012:role/deploy-role"),
            "SPECIFIC",
        )

    def test_iam_prefix_wildcard_is_scoped_prefix(self):
        self.assertEqual(
            classify("arn:aws:iam::123456789012:policy/prod-*"),
            "SCOPED_PREFIX",
        )

    def test_s3_object_prefix_wildcard_is_scoped_prefix(self):
        self.assertEqual(
            classify("arn:aws:s3:::my-bucket/uploads/*"),
            "SCOPED_PREFIX",
        )

    def test_non_string_input_returns_none(self):
        self.assertIsNone(classify(None))
        self.assertIsNone(classify(123))

    def test_malformed_iam_arn_falls_through_safely(self):
        result = classify("arn:aws:iam::123456789012:root")
        self.assertIn(result, ("SPECIFIC", "SCOPED_PREFIX", "UNCONSTRAINED"))


class TestAnalyzeResources(unittest.TestCase):
    def test_unconstrained_role_wildcard_is_flagged(self):
        findings = analyze("arn:aws:iam::123456789012:role/*")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Type"], "UNCONSTRAINED")

    def test_specific_resource_is_not_flagged(self):
        findings = analyze("arn:aws:iam::123456789012:role/deploy-role")
        self.assertEqual(findings, [])

    def test_list_of_resources_flags_only_risky_ones(self):
        resources = [
            "arn:aws:iam::123456789012:role/deploy-role",
            "arn:aws:iam::123456789012:role/*",
        ]
        findings = analyze(resources)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Resource"], "arn:aws:iam::123456789012:role/*")


class TestSetDefaultPolicyVersion(unittest.TestCase):
    def test_iam_09_wildcard_detected(self):
        policy = [{
            "PolicyName": "SetPolicyVersionPolicy",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:SetDefaultPolicyVersion",
                        "Resource": "*",
                    }
                ]
            },
        }]
        findings = analyze_policy_for_set_policy_version(policy, "Role", "TestRole")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["RuleID"], "IAM_09")
        self.assertEqual(findings[0]["Severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()