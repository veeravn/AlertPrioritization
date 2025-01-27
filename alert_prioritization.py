import pandas as pd
import argparse
import json
from datetime import datetime, timedelta
from concurrent.futures import ProcessPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Helper Functions
def parse_timestamp(timestamp):
    try:
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise ValueError(f"Invalid timestamp format: {timestamp}")

def determine_priority(risk_score):
    if risk_score > 15:
        return 'High'
    elif risk_score > 8:
        return 'Medium'
    else:
        return 'Low'

def compute_frequency_scores(data, config):
    time_window_minutes = int(config["frequency_threshold"]["time_window"].rstrip("m"))
    time_window = timedelta(minutes=time_window_minutes)
    count_threshold = config['frequency_threshold']['count']

    # Compute frequency score for each alert
    data = data.sort_values(by='timestamp')
    frequency_scores = []

    for i, row in data.iterrows():
        start_time = row['timestamp'] - time_window
        recent_alerts = data[(data['source_ip'] == row['source_ip']) & (data['timestamp'] > start_time)]
        score = len(recent_alerts) * config['frequency_weight'] if len(recent_alerts) >= count_threshold else 0
        frequency_scores.append(score)

    data['frequency_score'] = frequency_scores
    return data

def compute_risk_scores(data, config):
    # Vectorized computation for risk scores
    data['severity_score'] = data['severity'] * config['severity_weight']
    data['blacklist_penalty'] = data['source_ip'].apply(lambda ip: 10 if ip in config['ip_blacklist'] else 0)
    data['role_score'] = data['user_role'].map(config['role_weights']).fillna(0) * config['role_weight']

    # Total risk score
    data['risk_score'] = (
        data['severity_score'] +
        data['frequency_score'] +
        data['role_score'] +
        data['blacklist_penalty']
    ).round(2)
    return data

def process_chunk(chunk, config):
    try:
        chunk['timestamp'] = pd.to_datetime(chunk['timestamp'])

        # Compute frequency scores
        chunk = compute_frequency_scores(chunk, config)

        # Compute risk scores
        chunk = compute_risk_scores(chunk, config)

        # Determine priority
        chunk['priority'] = chunk['risk_score'].apply(determine_priority)
        return chunk[['alert_id', 'risk_score', 'priority']]
    except Exception as e:
        logging.error(f"Error processing chunk: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    try:
        # Parse arguments
        parser = argparse.ArgumentParser(prog='Scalable Alert Prioritization')
        parser.add_argument("dataFile", help="The CSV file with alerts to parse.")
        parser.add_argument("configFile", help="The risk scoring JSON config file.")
        args = parser.parse_args()

        # Read configuration
        with open(args.configFile) as f:
            config = json.load(f)

        chunk_size = 10000  # Adjust based on memory and dataset size
        results = []

        # Process data in chunks using parallel processing
        with ProcessPoolExecutor() as executor:
            futures = []

            for chunk in pd.read_csv(args.dataFile, chunksize=chunk_size):
                futures.append(executor.submit(process_chunk, chunk, config))

            for future in futures:
                result = future.result()
                if not result.empty:
                    results.append(result)

        # Combine all results
        final_df = pd.concat(results, ignore_index=True)

        # Save to CSV
        final_df.to_csv('alerts_with_priority.csv', index=False)

        # Log summary
        priority_summary = final_df['priority'].value_counts()
        logging.info("Priority Summary:")
        logging.info(priority_summary)

    except Exception as e:
        logging.error(f"An error occurred: {e}")