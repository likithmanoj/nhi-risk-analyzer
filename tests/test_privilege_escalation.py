"""
Unit tests for nhi.risk.rules.privilege_escalation's resource classifier.

These are pure function tests — no AWS calls, no mocking needed, since
classify_resources_for_privilege_escalation only operates on strings.
That's the payoff of the offline-first design: this whole suite runs
in milliseconds and catches regressions like the one this file guards
against (an extra '*' in the arn:aws:iam:: prefix check silently
reintroduced the exact bug we'd already fixed once).

Run with:
    python3 -m unittest discover -s tests
or just this file:
    python3 -m unittest tests.test_privilege_escalation
"""

import unittest

from nhi.risk.rules.privilege_escalation import (
    classify_resources_for_privilege_escalation as classify,
    analyze_resources_for_privilege_escalation as analyze,
)


class TestClassifyResourcesForPrivilegeEscalation(unittest.TestCase):

    def test_bare_wildcard_is_unconstrained(self):
        self.assertEqual(classify("*"), "UNCONSTRAINED")

    def test_fully_wildcarded_arn_is_unconstrained(self):
        self.assertEqual(classify("arn:aws:*:*:*:*"), "UNCONSTRAINED")

    def test_iam_identity_name_wildcard_is_unconstrained(self):
        """
        The regression case: role/*, policy/*, user/*, group/* all
        match EVERY identity of that type in the account — that's
        not real scoping, so it must classify as UNCONSTRAINED, not
        SCOPED_PREFIX. This is the exact bug that got reintroduced
        when the prefix check was accidentally written as
        'arn:aws:iam::*' instead of 'arn:aws:iam::'.
        """
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
        """
        A single, named IAM resource with no wildcard at all should
        NOT be flagged by this classifier — that's correct, because
        catching "PassRole scoped to one specific privileged role" is
        a different, harder problem (needs the permission-chain /
        AssumeRole analysis discussed separately), not something this
        wildcard classifier is meant to catch.
        """
        self.assertEqual(
            classify("arn:aws:iam::123456789012:role/deploy-role"),
            "SPECIFIC",
        )

    def test_iam_prefix_wildcard_is_scoped_prefix(self):
        """
        role/prod-* narrows to roles starting with 'prod-' — not a
        bare wildcard, so current behavior treats it as SCOPED_PREFIX.
        Flagging this as worth a second look: unlike an S3 object
        prefix, an IAM name prefix like this can still match many
        roles in the account, so SCOPED_PREFIX (-> LOW severity) may
        be too generous here. Not asserting a "correct" answer yet —
        this test just pins down current behavior so a deliberate
        change shows up as an intentional diff, not a silent one.
        """
        self.assertEqual(
            classify("arn:aws:iam::123456789012:policy/prod-*"),
            "SCOPED_PREFIX",
        )

    def test_s3_object_prefix_wildcard_is_scoped_prefix(self):
        """
        A genuinely narrow, non-identity resource wildcard (an S3
        prefix) should stay SCOPED_PREFIX / LOW risk — this is the
        case the SCOPED_PREFIX category exists for.
        """
        self.assertEqual(
            classify("arn:aws:s3:::my-bucket/uploads/*"),
            "SCOPED_PREFIX",
        )

    def test_non_string_input_returns_none(self):
        self.assertIsNone(classify(None))
        self.assertIsNone(classify(123))

    def test_malformed_iam_arn_falls_through_safely(self):
        """
        An IAM ARN missing the expected '/' segment shouldn't crash
        the split logic — it should just fall through to the generic
        classification instead of raising.
        """
        # No '/' after the account ID — doesn't match the expected
        # arn:aws:iam::<account>:<type>/<name> shape.
        result = classify("arn:aws:iam::123456789012:root")
        self.assertIn(result, ("SPECIFIC", "SCOPED_PREFIX", "UNCONSTRAINED"))


class TestAnalyzeResourcesForPrivilegeEscalation(unittest.TestCase):
    """
    These test the wrapper function that risk rules actually call —
    confirming UNCONSTRAINED/SCOPED_PREFIX resources are flagged and
    SPECIFIC resources are correctly left out of findings entirely.
    """

    def test_unconstrained_role_wildcard_is_flagged(self):
        findings = analyze("arn:aws:iam::123456789012:role/*")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Type"], "UNCONSTRAINED")

    def test_specific_resource_is_not_flagged(self):
        findings = analyze("arn:aws:iam::123456789012:role/deploy-role")
        self.assertEqual(findings, [])

    def test_list_of_resources_flags_only_risky_ones(self):
        resources = [
            "arn:aws:iam::123456789012:role/deploy-role",  # SPECIFIC — skip
            "arn:aws:iam::123456789012:role/*",             # UNCONSTRAINED — flag
        ]
        findings = analyze(resources)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Resource"], "arn:aws:iam::123456789012:role/*")


if __name__ == "__main__":
    unittest.main()