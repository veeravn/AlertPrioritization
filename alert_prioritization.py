import os
import pandas as pd
import json
from datetime import timedelta
from collections import defaultdict
from multiprocessing import Pool
import argparse

# Load configuration from JSON file
def load_config(config_file='config.json'):
    try:
        # Check if the config file exists
        if not os.path.exists(config_file):
            raise FileNotFoundError(f"Config file '{config_file}' not found.")
        
        with open(config_file, 'r') as file:
            config = json.load(file)
        
        # Validate the required config keys
        required_keys = [
            "alert_type_weights", "frequency_threshold", "role_weights", "ip_blacklist",
            "severity_weight", "frequency_weight", "role_weight"
        ]
        
        for key in required_keys:
            if key not in config:
                raise KeyError(f"Missing required key '{key}' in config file.")
        
        return config
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
        raise
    except json.JSONDecodeError:
        print(f"Error: The config file '{config_file}' is not valid JSON.")
        raise
    except KeyError as e:
        print(f"Error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error while loading config: {e}")
        raise

# Precompute alert frequency in the dataset (vectorized approach)
def precompute_alert_frequency(alert_df, config):
    try:
        # Convert timestamp to datetime
        alert_df['timestamp'] = pd.to_datetime(alert_df['timestamp'])
        
        # Create a new column, time_window_start, which is the start of the time window for each alert
        alert_df['time_window_start'] = alert_df['timestamp'] - timedelta(minutes=int(config['frequency_threshold']['time_window'][:-1]))
        
        # Keep track of how many alerts have been triggered for each specific combination of target_ip and time_window_start. 
        # The idea is to count the number of alerts that occurred within the same time window for a specific target IP.
        frequency_dict = defaultdict(int)
        for idx, row in alert_df.iterrows():
            key = (row['target_ip'], row['time_window_start'])
            frequency_dict[key] += row['alert_count']
        
        # Store precomputed frequency in the dataframe
        alert_df['precomputed_frequency'] = alert_df.apply(
            lambda row: frequency_dict.get((row['target_ip'], row['time_window_start']), 0), axis=1
        )
        return alert_df
    except KeyError as e:
        print(f"Error: Missing expected column in input CSV - {e}")
        exit(1)
    except Exception as e:
        print(f"Error while precomputing alert frequencies: {e}")
        exit(1)

# Calculate risk score for an alert (optimized with vectorized operations)
def calculate_risk_score(alert, config):
    try:
        # Get weight for the alert type
        alert_type_weight = config['alert_type_weights'].get(alert['alert_type'], 0)
        
        # Get severity weight
        severity_weight = alert['severity'] * config['severity_weight']
        
        # Check if the source IP is blacklisted
        blacklist_weight = 10 if alert['source_ip'] in config['ip_blacklist'] else 0
        
        # Check frequency (precomputed)
        frequency_weight = 1 if alert['precomputed_frequency'] >= config['frequency_threshold']['count'] else 0
        
        # Get weight for the target role
        role_weight = config['role_weights'].get(alert['user_role'], 0)
        
        # Calculate the total risk score
        risk_score = (alert_type_weight + severity_weight + blacklist_weight + frequency_weight + role_weight)
        
        return risk_score
    except KeyError as e:
        print(f"Error: Missing expected field in alert data - {e}")
        exit(1)
    except Exception as e:
        print(f"Unexpected error while calculating risk score: {e}")
        exit(1)

# Classify the alert priority based on risk score
def classify_priority(risk_score):
    if risk_score > 15:
        return 'High'
    elif risk_score > 8:
        return 'Medium'
    else:
        return 'Low'

# Function to process a chunk of data and return results (parallelized)
def process_chunk(chunk, config):
    try:
        results = []
        alert_df = precompute_alert_frequency(chunk, config)
        for _, alert in alert_df.iterrows():
            risk_score = calculate_risk_score(alert, config)
            priority = classify_priority(risk_score)
            results.append({'alert_id': alert['alert_id'], 'risk_score': risk_score, 'priority': priority})
        return results
    
    except Exception as e:
        print(f"Error processing chunk: {e}")
        return []

# Function to read CSV in chunks, process and store results
def process_alerts(dataFile, configFile):
    try:
        # Load config and initialize variables
        config = load_config(configFile)
        chunk_size = 10000  # Adjust based on memory limitations and dataset size
        results = []
        
        # Read CSV in chunks
        # Set up multiprocessing pool for parallel processing
        with Pool() as pool:
            chunks = pd.read_csv(dataFile, chunksize=chunk_size)
            for chunk in chunks:
                result = pool.apply(process_chunk, (chunk, config))
                results.extend(result)
        
        # Convert results to DataFrame and save to CSV
        results_df = pd.DataFrame(results)
        results_df.to_csv('alerts_with_priority.csv', index=False)
        
        # Return summary of priorities
        priority_summary = results_df['priority'].value_counts()
        return priority_summary
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    except pd.errors.ParserError:
        print(f"Error: The input CSV file '{input_file}' could not be parsed. Ensure it's correctly formatted.")
        exit(1)
    except Exception as e:
        print(f"Unexpected error while processing alerts: {e}")
        exit(1)

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(prog='Scalable Alert Prioritization')
    parser.add_argument("dataFile", help="The CSV file with alerts to parse.")
    parser.add_argument("configFile", help="The risk scoring JSON config file.")
    args = parser.parse_args()

    # Process alerts
    priority_summary = process_alerts(args.dataFile, args.configFile)
    print("Priority Summary:")
    print(priority_summary)
