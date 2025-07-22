# Behavioral Intrusion Detection System

*Author*: elryan7\

*Repository*: https://github.com/elryan7/behavioral-ids\

*License*: MIT

## Description

This Python tool implements a behavioral Intrusion Detection System (IDS) that monitors network traffic in real-time and detects anomalies based on traffic volume and connection patterns using statistical analysis.

## Features

- Real-time network traffic monitoring
- Anomaly detection based on traffic volume and IP connections
- Detailed logging and alerting
- Customizable thresholds for anomaly detection

## Prerequisites

- Python 3.8+
- Libraries: `scapy`, `numpy`, `pandas`
- Root/admin privileges for packet capture (on Linux, use `sudo`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/elryan7/behavioral-ids.git
   cd behavioral-ids
   ```
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the IDS with:

```bash
sudo python3 behavioral_ids.py
```

- Alerts are logged to `anomaly_alerts.log`.
- Traffic statistics are saved to `traffic_stats.csv`.

## Example Output

```
ALERT: Anomaly detected! IP 192.168.1.100 exceeds traffic volume threshold (500 packets/min).
```

## Project Structure

- `behavioral_ids.py`: Main script for IDS
- `requirements.txt`: List of required Python libraries
- `anomaly_alerts.log`: Log file for alerts
- `traffic_stats.csv`: Traffic statistics file

