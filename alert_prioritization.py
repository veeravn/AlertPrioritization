import pandas as pd
import argparse
import json
from datetime import datetime, timedelta
print(pd)

# Helper Functions
def parse_timestamp(timestamp):
    try:
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise ValueError(f"Invalid timestamp format: {timestamp}")
# Function to determine alert priority
def determine_priority(risk_score):
    if risk_score > 15:
        return 'High'
    elif risk_score > 8:
        return 'Medium'
    else:
        return 'Low'

def compute_frequency_score(alert, data, config):
    # Frequency Weight (alert_count within a time window)
    try:
        time_window_minutes = int(config["frequency_threshold"]["time_window"].rstrip("m"))
    except (ValueError, AttributeError):
        raise ValueError("Invalid time_window format in configuration. Expected a string ending with 'm', e.g., '10m'.")
    
    time_window = timedelta(minutes=time_window_minutes)
    count_threshold = config['frequency_threshold']['count']
    
    alert_time = pd.to_datetime(alert['timestamp'])
    recent_alerts = data[(data['source_ip'] == alert['source_ip']) &
                               (data['timestamp'] > (alert_time - time_window))]

    if len(recent_alerts) >= count_threshold:
        return len(recent_alerts) * config['frequency_weight']
    else:
        return 0

def compute_blacklist_penalty(alert, config):
    return 10 if alert["source_ip"] in config["ip_blacklist"] else 0

def compute_risk_score(alert, config, data):

    total_score = 0
    # Severity Contribution
    total_score += alert["severity"] * config["severity_weight"]

    # Frequency Contribution
    total_score += compute_frequency_score(alert, data, config) * config["frequency_weight"]

    # Role Contribution
    total_score += config["role_weights"].get(alert["user_role"], 0) * config["role_weight"]

    # Blacklist Penalty
    total_score += compute_blacklist_penalty(alert, config)
    return round(total_score, 2)

# Compute risk scores
try:
    # Parse data file and config file from command line arguments
    parser = argparse.ArgumentParser(prog='Alert Prioritization', usage='%(prog)s [options]')
    parser.add_argument("dataFile", help="The CSV file with alerts to parse.")
    parser.add_argument("configFile", type=int, help="The risk scoring json config file.")
    args = parser.parse_args()
    parser.print_help()

    # read alerts csv data file
    alerts = pd.read_csv(args.dataFile)

    # read the config json file
    with open(args.configFile) as f:
        config = json.load(f)
    
    # Convert the timestamp to datetime
    alerts['timestamp'] = pd.to_datetime(alerts['timestamp'])
    # List to store results
    results = []

    # Process each alert
    for index, alert in alerts.iterrows():
        risk_score = compute_risk_score(alert, config, alerts)
        priority = determine_priority(risk_score)
        results.append({
            'alert_id': alert['alert_id'],
            'risk_score': risk_score,
            'priority': priority
        })
    # Create DataFrame for output
    output_df = pd.DataFrame(results)

    # Save the output to a new CSV
    output_df.to_csv('alerts_with_priority.csv', index=False)
    
    # Bonus: Summary of priorities
    priority_summary = output_df['priority'].value_counts()
    print("Priority Summary:")
    print(priority_summary)

except Exception as e:
    print(f"An error occurred: {e}")       
        

