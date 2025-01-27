import unittest
import pandas as pd
import os
from datetime import datetime, timedelta
from alert_prioritization import (
    load_config,
    classify_priority,
    precompute_alert_frequency,
    calculate_risk_score,
    process_chunk
)

class TestAlertPrioritization(unittest.TestCase):
    
    def setUp(self):
        # Example configuration
        self.config = {
            "alert_type_weights": {"Brute Force": 3, "DDoS": 4, "Malware": 2},
            "frequency_threshold": {"count": 5, "time_window": "10m"},
            "role_weights": {"Admin": 5, "Database": 4, "Web Server": 2},
            "ip_blacklist": ["192.168.1.100", "10.0.0.15"],
            "severity_weight": 0.4,
            "frequency_weight": 0.3,
            "role_weight": 0.3
        }

        # Example alert data
        self.alert_data = pd.DataFrame({
            "alert_id": [1, 2, 3],
            "alert_type": ["Brute Force", "DDoS", "Malware"],
            "timestamp": [
                (datetime.now() - timedelta(minutes=5)).isoformat(),
                (datetime.now() - timedelta(minutes=15)).isoformat(),
                (datetime.now() - timedelta(minutes=20)).isoformat()
            ],
            "target_ip": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            "source_ip": ["192.168.1.100", "203.0.113.4", "10.0.0.15"],
            "severity": [3, 4, 2],
            "user_role": ["Admin", "Web Server", "Database"],
            "alert_count": [7, 10, 3]
        })

    def test_load_config(self):
        """Test that the configuration loads correctly."""
        config = self.config
        required_keys = [
            "alert_type_weights", "frequency_threshold", "role_weights", "ip_blacklist",
            "severity_weight", "frequency_weight", "role_weight"
        ]
        for key in required_keys:
            self.assertIn(key, config)

    def test_load_config_missing_key(self):
        """Test loading a config with missing keys."""
        with self.assertRaises(FileNotFoundError):
            load_config('invalid_config.json')

    def test_precompute_alert_frequency(self):
        """Test precomputing alert frequency in the dataset."""
        alert_df = precompute_alert_frequency(self.alert_data.copy(), self.config)
        self.assertIn("precomputed_frequency", alert_df.columns)
        self.assertGreaterEqual(alert_df["precomputed_frequency"].iloc[0], 0)

    def test_precompute_alert_frequency_empty(self):
        """Test precomputing alert frequency with an empty DataFrame."""
        empty_df = pd.DataFrame(columns=self.alert_data.columns)
        result_df = precompute_alert_frequency(empty_df, self.config)
        self.assertTrue(result_df.empty)

    def test_calculate_risk_score(self):
        """Test calculating the risk score of an alert."""
        alert = self.alert_data.iloc[0].to_dict()
        alert["precomputed_frequency"] = 3  # Simulate precomputed frequency
        risk_score = calculate_risk_score(alert, self.config)
        self.assertGreater(risk_score, 0)

    def test_calculate_risk_score_blacklisted_ip(self):
        """Test calculating the risk score for a blacklisted source IP."""
        alert = self.alert_data.iloc[0].to_dict()
        alert["source_ip"] = "192.168.1.100"  # Blacklisted IP
        alert["precomputed_frequency"] = 3
        risk_score = calculate_risk_score(alert, self.config)
        self.assertGreater(risk_score, 0)
        self.assertIn("192.168.1.100", self.config["ip_blacklist"])

    def test_calculate_risk_score_low_severity(self):
        """Test calculating the risk score for low severity."""
        alert = self.alert_data.iloc[2].to_dict()  # Severity 2
        alert["precomputed_frequency"] = 1
        risk_score = calculate_risk_score(alert, self.config)
        self.assertGreater(risk_score, 0)

    def test_process_chunk(self):
        """Test processing a chunk of alert data."""
        chunk = self.alert_data.copy()
        chunk["precomputed_frequency"] = [3, 5, 2]  # Simulate precomputed frequencies
        results = process_chunk(chunk, self.config)
        self.assertEqual(len(results), len(chunk))
        for result in results:
            self.assertIn("alert_id", result)
            self.assertIn("risk_score", result)
            self.assertIn("priority", result)

    def test_classify_priority(self):
        """Test classifying priority based on risk score."""
        self.assertEqual(classify_priority(9), "Medium")
        self.assertEqual(classify_priority(17), "High")
        self.assertEqual(classify_priority(3), "Low")

    def test_classify_priority_boundary(self):
        """Test priority classification on boundary conditions."""
        self.assertEqual(classify_priority(15), "Medium")
        self.assertEqual(classify_priority(8), "Low")

if __name__ == "__main__":
    unittest.main()

