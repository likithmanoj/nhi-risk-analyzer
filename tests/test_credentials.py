from datetime import datetime, timedelta, timezone
import unittest

from nhi.risk.rules.credentials import analyze_unused_keys


class TestAnalyzeUnusedKeys(unittest.TestCase):

  def setUp(self):
    self.now = datetime.now(timezone.utc)
    self.username = 'test-security-user'

  def test_active_key_unused_over_30_days_triggers_finding(self):
    """Key used 45 days ago should trigger an 'Unused in 30 days' finding."""
    last_used_45_days_ago = (self.now - timedelta(days=45)).isoformat()

    mock_keys = [{
        'AccessKeyId': 'AKIA1111111111111111',
        'Status': 'Active',
        'CreateDate': (self.now - timedelta(days=60)).isoformat(),
        'AccessKeyLastUsed': {
            'LastUsedDate': last_used_45_days_ago,
            'ServiceName': 's3',
            'Region': 'us-east-1',
        },
    }]

    findings = analyze_unused_keys(mock_keys, self.username)

    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]['Finding'], 'Key Unused in 30 days')
    self.assertEqual(findings[0]['TargetID'], 'AKIA1111111111111111')
    self.assertEqual(findings[0]['AgeInDays'], 45)

  def test_key_never_used_created_over_30_days_ago_triggers_finding(self):
    """Key with LastUsedDate=None created 40 days ago should trigger 'since inception'."""
    mock_keys = [{
        'AccessKeyId': 'AKIA2222222222222222',
        'Status': 'Active',
        'CreateDate': (self.now - timedelta(days=40)).isoformat(),
        'AccessKeyLastUsed': {
            'LastUsedDate': None,
            'ServiceName': 'N/A',
            'Region': 'N/A',
        },
    }]

    findings = analyze_unused_keys(mock_keys, self.username)

    self.assertEqual(len(findings), 1)
    self.assertEqual(
        findings[0]['Finding'], 'Key Unused since its inception'
    )
    self.assertEqual(findings[0]['TargetID'], 'AKIA2222222222222222')
    self.assertEqual(findings[0]['AgeInDays'], 40)

  def test_inactive_keys_are_ignored(self):
    """Inactive keys should be skipped even if they are >30 days old."""
    mock_keys = [{
        'AccessKeyId': 'AKIA3333333333333333',
        'Status': 'Inactive',
        'CreateDate': (self.now - timedelta(days=100)).isoformat(),
        'AccessKeyLastUsed': {'LastUsedDate': None},
    }]

    findings = analyze_unused_keys(mock_keys, self.username)
    self.assertEqual(len(findings), 0)

  def test_recently_used_key_produces_no_findings(self):
    """Key used 5 days ago should not trigger any findings."""
    recently_used = (self.now - timedelta(days=5)).isoformat()

    mock_keys = [{
        'AccessKeyId': 'AKIA4444444444444444',
        'Status': 'Active',
        'CreateDate': (self.now - timedelta(days=10)).isoformat(),
        'AccessKeyLastUsed': {
            'LastUsedDate': recently_used,
            'ServiceName': 'iam',
            'Region': 'us-east-1',
        },
    }]

    findings = analyze_unused_keys(mock_keys, self.username)
    self.assertEqual(len(findings), 0)


if __name__ == '__main__':
  unittest.main()