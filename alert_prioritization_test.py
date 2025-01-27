import unittest
import pandas as pd
import json
from io import StringIO
from alert_prioritization import (
    parse_timestamp,
    determine_priority,
    compute_frequency_scores,
    compute_risk_scores,
    process_chunk
)

class TestAlertPrioritization(unittest.TestCase):
    
    def setUp(self):
        # Mock configuration
        self.config = {
            "severity_weight": 1.5,
            "frequency_weight": 2.0,
            "role_weight": 1.2,
            "frequency_threshold": {
                "time_window": "10m",
                "count": 2
            },
            "ip_blacklist": ["192.168.1.1", "10.0.0.1"],
            "role_weights": {
                "admin": 5,
                "user": 2,
                "guest": 1
            }
        }

        # Mock data
        self.mock_csv_data = """alert_id,timestamp,source_ip,severity,user_role
        1,2025-01-27T10:00:00,192.168.1.1,10,admin
        2,2025-01-27T10:05:00,10.0.0.2,8,user
        3,2025-01-27T10:08:00,10.0.0.2,5,guest
        4,2025-01-27T10:12:00,192.168.1.1,7,user
        5,2025-01-27T10:15:00,10.0.0.1,9,admin
        """

        self.alerts = pd.read_csv(StringIO(self.mock_csv_data))
        self.alerts['timestamp'] = pd.to_datetime(self.alerts['timestamp'])

    def test_parse_timestamp(self):
        timestamp = "2025-01-27T10:00:00"
        parsed = parse_timestamp(timestamp)
        self.assertEqual(parsed, pd.Timestamp("2025-01-27T10:00:00"))

    def test_parse_invalid_timestamp(self):
        with self.assertRaises(ValueError):
            parse_timestamp("invalid-timestamp")

    def test_determine_priority(self):
        self.assertEqual(determine_priority(16), 'High')
        self.assertEqual(determine_priority(12), 'Medium')
        self.assertEqual(determine_priority(5), 'Low')

    def test_compute_frequency_scores(self):
        result = compute_frequency_scores(self.alerts, self.config)
        self.assertIn('frequency_score', result.columns)
        # Check specific frequency score values
        self.assertEqual(result.loc[0, 'frequency_score'], 0)  # First row has no prior alerts
        self.assertGreater(result.loc[1, 'frequency_score'], 0)  # Alert with prior within 10m
        self.assertEqual(result.loc[2, 'frequency_score'], 0)  # Guest role, low frequency

    def test_compute_frequency_scores_blacklist(self):
        result = compute_frequency_scores(self.alerts, self.config)
        self.assertEqual(result.loc[0, 'frequency_score'], 0)  # Blacklisted IP should not affect frequency

    def test_compute_risk_scores(self):
        self.alerts['frequency_score'] = [0, 4, 0, 4, 0]  # Mock frequency scores
        result = compute_risk_scores(self.alerts, self.config)
        self.assertIn('risk_score', result.columns)
        # Check specific risk score values
        self.assertGreater(result.loc[0, 'risk_score'], 0)
        self.assertGreater(result.loc[1, 'risk_score'], result.loc[2, 'risk_score'])  # Severity difference
        self.assertGreater(result.loc[0, 'risk_score'], result.loc[4, 'risk_score'])  # Role weight difference

    def test_compute_risk_scores_blacklist_penalty(self):
        self.alerts['frequency_score'] = [0, 0, 0, 0, 0]  # Mock frequency scores
        result = compute_risk_scores(self.alerts, self.config)
        self.assertEqual(result.loc[0, 'risk_score'], result.loc[0, 'severity'] * self.config['severity_weight'] + 10)  # Blacklist penalty applied

    def test_process_chunk(self):
        result = process_chunk(self.alerts, self.config)
        self.assertIn('alert_id', result.columns)
        self.assertIn('risk_score', result.columns)
        self.assertIn('priority', result.columns)
        # Check that all rows are processed
        self.assertEqual(len(result), len(self.alerts))

    def test_process_chunk_empty(self):
        empty_alerts = pd.DataFrame(columns=self.alerts.columns)
        result = process_chunk(empty_alerts, self.config)
        self.assertTrue(result.empty)

    def test_process_chunk_invalid_data(self):
        invalid_alerts = self.alerts.copy()
        invalid_alerts.loc[0, 'timestamp'] = 'invalid-timestamp'
        with self.assertLogs(level='ERROR') as log:
            result = process_chunk(invalid_alerts, self.config)
            self.assertTrue(result.empty)
            self.assertIn('ERROR', log.output[0])

if __name__ == '__main__':
    unittest.main()
