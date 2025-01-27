import unittest
from unittest.mock import patch, MagicMock
import pandas as pd
from datetime import datetime
import json
from io import StringIO
from alert_prioritization import parse_timestamp, determine_priority, compute_frequency_score, compute_blacklist_penalty, compute_risk_score

class TestAlertPrioritization(unittest.TestCase):
    
    # Test parse_timestamp function
    def test_parse_timestamp_valid(self):
        timestamp = "2025-01-01T12:00:00"
        expected = datetime(2025, 1, 1, 12, 0, 0)
        self.assertEqual(parse_timestamp(timestamp), expected)
    
    def test_parse_timestamp_invalid(self):
        timestamp = "01-01-2025 12:00:00"
        with self.assertRaises(ValueError):
            parse_timestamp(timestamp)

    # Test determine_priority function
    def test_determine_priority_high(self):
        self.assertEqual(determine_priority(16), 'High')
    
    def test_determine_priority_medium(self):
        self.assertEqual(determine_priority(10), 'Medium')
    
    def test_determine_priority_low(self):
        self.assertEqual(determine_priority(5), 'Low')

    # Test compute_frequency_score function
    @patch('pandas.to_datetime')
    def test_compute_frequency_score_high(self, mock_to_datetime):
        alert = {"source_ip": "192.168.1.1", "timestamp": "2025-01-01T12:00:00"}
        data = pd.DataFrame({
            'source_ip': ["192.168.1.1", "192.168.1.1"],
            'timestamp': ["2025-01-01T12:00:01", "2025-01-01T12:00:02"],
        })
        config = {
            "frequency_threshold": {"time_window": "1m", "count": 2},
            "frequency_weight": 2
        }
        mock_to_datetime.return_value = datetime(2025, 1, 1, 12, 0, 0)
        
        result = compute_frequency_score(alert, data, config)
        self.assertEqual(result, 4)  # 2 alerts * frequency_weight of 2
    
    @patch('pandas.to_datetime')
    def test_compute_frequency_score_low(self, mock_to_datetime):
        alert = {"source_ip": "192.168.1.1", "timestamp": "2025-01-01T12:00:00"}
        data = pd.DataFrame({
            'source_ip': ["192.168.1.1"],
            'timestamp': ["2025-01-01T12:00:02"],
        })
        config = {
            "frequency_threshold": {"time_window": "1m", "count": 2},
            "frequency_weight": 2
        }
        mock_to_datetime.return_value = datetime(2025, 1, 1, 12, 0, 0)
        
        result = compute_frequency_score(alert, data, config)
        self.assertEqual(result, 0)

    # Test compute_blacklist_penalty function
    def test_compute_blacklist_penalty_blacklisted(self):
        alert = {"source_ip": "192.168.1.1"}
        config = {"ip_blacklist": ["192.168.1.1"]}
        result = compute_blacklist_penalty(alert, config)
        self.assertEqual(result, 10)

    def test_compute_blacklist_penalty_non_blacklisted(self):
        alert = {"source_ip": "192.168.1.2"}
        config = {"ip_blacklist": ["192.168.1.1"]}
        result = compute_blacklist_penalty(alert, config)
        self.assertEqual(result, 0)

    # Test compute_risk_score function
    @patch('pandas.to_datetime')
    def test_compute_risk_score(self, mock_to_datetime):
        alert = {
            "alert_id": 1,
            "severity": 5,
            "user_role": "admin",
            "source_ip": "192.168.1.1",
            "timestamp": "2025-01-01T12:00:00"
        }
        data = pd.DataFrame({
            'alert_id': [1],
            'source_ip': ["192.168.1.1"],
            'timestamp': ["2025-01-01T12:00:00"],
            'severity': [5],
            'user_role': ["admin"]
        })
        config = {
            "frequency_threshold": {"time_window": "1m", "count": 2},
            "frequency_weight": 2,
            "severity_weight": 1,
            "role_weights": {"admin": 3},
            "role_weight": 2,
            "ip_blacklist": ["192.168.1.1"]
        }
        mock_to_datetime.return_value = datetime(2025, 1, 1, 12, 0, 0)
        
        result = compute_risk_score(alert, config, data)
        expected_risk_score = 5 * 1 + 0 + 3 * 2 + 10  # Severity + Frequency + Role + Blacklist Penalty
        self.assertEqual(result, expected_risk_score)

    # Test file parsing and integration (mocking pandas read_csv and json loading)
    @patch('pandas.read_csv')
    @patch('builtins.open', new_callable=MagicMock)
    def test_main_program_logic(self, mock_open, mock_read_csv):
        mock_read_csv.return_value = pd.DataFrame({
            'alert_id': [1],
            'source_ip': ["192.168.1.1"],
            'timestamp': ["2025-01-01T12:00:00"],
            'severity': [5],
            'user_role': ["admin"]
        })

        mock_open.return_value.__enter__.return_value = MagicMock(read=lambda: json.dumps({
            "frequency_threshold": {"time_window": "1m", "count": 2},
            "frequency_weight": 2,
            "severity_weight": 1,
            "role_weights": {"admin": 3},
            "role_weight": 2,
            "ip_blacklist": ["192.168.1.1"]
        }))

        # Call the main function logic (would typically be in your script)
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            # Assuming you have a function that runs your script, e.g., `run_alert_prioritization`
            # run_alert_prioritization() 
            print("Test complete")

        # Check that output is correct, e.g., you might check the expected printed text
        output = mock_stdout.getvalue()
        self.assertIn("Priority Summary:", output)

if __name__ == '__main__':
    unittest.main()
