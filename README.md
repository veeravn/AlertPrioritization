# Alert Prioritization Script

This Python script is designed to process security alerts, compute risk scores based on a set of configurable parameters, and determine the priority of each alert. It uses machine learning-like techniques to assign a priority (High, Medium, or Low) based on factors like severity, frequency, role, and whether the source IP is blacklisted.

## Features

- **Compute Risk Score**: Calculates a risk score for each alert based on severity, frequency of alerts from the same source IP, user role, and blacklist penalties.
- **Determine Priority**: Assigns a priority to each alert (`High`, `Medium`, or `Low`) based on the calculated risk score.
- **Input Files**:
  - **CSV file**: Contains the security alerts.
  - **JSON config file**: Defines the scoring parameters (frequency threshold, weightings, severity weights, role weights, and blacklist).
- **Output**: Saves the processed alerts with their respective priorities into a new CSV file and prints a summary of the priorities.

---

## Requirements

- Python 3.x
- `pandas` library version 2.2.0
- `argparse` (built-in Python module)
- `json` (built-in Python module)
- `unittest` for testing (built-in Python module)

You can install the required libraries using pip if they aren't already installed:

```bash
pip install pandas==2.2.0
```

## Setup

1. **Download the repository** or copy the script file to your local machine.
2. **Prepare the input files**:
   - A CSV file containing the security alerts.
   - A JSON configuration file to specify scoring thresholds, weights, and blacklist rules.

### Sample CSV (`alerts.csv`)

This is the format for your CSV file containing the alerts:

```csv
alert_id,source_ip,timestamp,severity,user_role
1,192.168.1.1,2025-01-01T12:00:00,5,admin
2,192.168.1.2,2025-01-01T12:05:00,3,guest
...
```

### Sample JSON Config (`config.json`)

The JSON file defines the parameters for scoring the alerts:

```json
{
  "frequency_threshold": {
    "time_window": "10m",
    "count": 3
  },
  "frequency_weight": 2,
  "severity_weight": 1,
  "role_weights": {
    "admin": 3,
    "guest": 1
  },
  "role_weight": 2,
  "ip_blacklist": ["192.168.1.1"]
}
```

- **`frequency_threshold.time_window`**: Defines the time window for considering recent alerts (e.g., "10m" for 10 minutes).
- **`frequency_threshold.count`**: The minimum number of alerts required within the time window to contribute to the risk score.
- **`frequency_weight`**: The weight applied to the frequency factor in the risk score.
- **`severity_weight`**: The weight applied to the severity of the alert.
- **`role_weights`**: A dictionary that defines the weight for each user role (e.g., `admin`, `guest`).
- **`role_weight`**: The weight applied to the role's contribution to the risk score.
- **`ip_blacklist`**: A list of blacklisted IP addresses to penalize in the risk score.  Assuming that the IP addresses in this list only affect the individual address and not a full CIDR block. (e.g., `192.168.1.0` means that only that IP is black listed and IP `192.168.1.1 ` would be fine)

## Running the Script

To run the script, use the following command in your terminal:

```bash
python alert_prioritization.py <dataFile> <configFile>
```

### Example:

```bash
python alert_prioritization.py alerts.csv config.json
```

This will:
1. Read the `alerts.csv` file containing security alerts.
2. Read the `config.json` file containing scoring configuration.
3. Process the alerts, calculate risk scores, and determine priorities.
4. Save the processed alerts with their calculated priorities into a new file `alerts_with_priority.csv`.
5. Print a summary of the priorities (e.g., how many alerts are classified as High, Medium, or Low).

## Output

The script will generate a new CSV file, `alerts_with_priority.csv`, with the following columns:

```csv
alert_id,risk_score,priority
1,15.5,High
2,8.0,Medium
...
```

Additionally, the terminal will print a summary of the priority counts:

```
Priority Summary:
High       5
Medium     3
Low        2
```

## Testing

Unit tests are included to verify the correctness of the individual functions. You can run the tests using Python's built-in `unittest` framework:

```bash
python -m unittest alert_prioritization_test.py
```

The test suite includes tests for:
- Parsing timestamps
- Determining priority
- Calculating frequency scores
- Checking blacklist penalties
- Calculating risk scores