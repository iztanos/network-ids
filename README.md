# Intrusion Detection System (IDS)

## Description
The Intrusion Detection System (IDS) is a comprehensive network security tool designed to detect and alert on suspicious activities such as port scans and ARP spoofing. The system includes email and Slack alert functionalities, a scheduled daily summary report, and a CLI interface for configuration. Key features include configurable time windows and thresholds for detecting port scans, detailed logging of packet data, and a robust database for storing alerts and generating reports. The system utilizes libraries such as `scapy` for packet processing, `apscheduler` for scheduling tasks, and `pytest` for unit testing.

## Features
- Email and Slack alerts for detected intrusions.
- Scheduled daily summary report.
- CLI interface for configuring the network interface, setting thresholds, and running in test mode.
- Unit tests using `pytest` and `scapy` PCAPs.

## Testing (incomplete)
To run the tests, use the following command:
```bash
pytest tests/test_ids.py
```

## Daily Summary Report
The daily summary report is generated at midnight and logged to `daily_report.log`. The report includes:
1. Count of new IPs detected.
2. Number of port scans detected.
3. Top suspicious IP.
4. Most probed port.

## Running the IDS
To run the IDS with the CLI interface, use the following command:
```bash
python main.py --interface <network_interface> --tcp-threshold <tcp_threshold> --udp-threshold <udp_threshold> [--test-mode]
```
Example:
```bash
python main.py --interface eth0 --tcp-threshold 4 --udp-threshold 6 --test-mode
```
This command will run the IDS on the `eth0` interface with the specified TCP and UDP thresholds in test mode.

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/iztanos/network-ids.git
   cd network-ids
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the email and Slack alert credentials:
   - Open `modules/alerts.py` and replace the placeholder email credentials with your actual email and password.
   - Open `modules/packet_processor.py` and replace the placeholder Slack webhook URL with your actual Slack webhook URL.
4. Initialize the database:
   ```bash
   python -c "from modules.database import init_db; init_db()"
   ```

### Running the IDS
To run the IDS with the CLI interface, use the following command:
```bash
python main.py --interface <network_interface> --tcp-threshold <tcp_threshold> --udp-threshold <udp_threshold> [--test-mode]
```
Example:
```bash
python main.py --interface eth0 --tcp-threshold 4 --udp-threshold 6 --test-mode
```
This command will run the IDS on the `eth0` interface with the specified TCP and UDP thresholds in test mode.

### Daily Summary Report
The daily summary report is generated at midnight and logged to `daily_report.log`. The report includes:
1. Count of new IPs detected.
2. Number of port scans detected.
3. Top suspicious IP.
4. Most probed port.

### Additional Information
- The system uses a time window of 10 seconds for detecting port scans.
- The threshold for the number of suspicious ports accessed to trigger an alert is configurable.
- Safe ports that are commonly used and can be ignored are defined in `config.py`.
- The system logs detailed packet data, including source and destination IPs, protocols, packet sizes, TTL values, and TCP flags.
- The database schema includes a table for storing alerts with details such as timestamp, IP, protocol, alert type, description, and ports.
- The system supports running in test mode, which allows for simulating the process without actual packet sniffing. (incomplete)

### Dependencies
The project depends on the following libraries:
- `scapy`: For packet processing and network analysis.
- `apscheduler`: For scheduling tasks such as generating daily reports.
- `pytest`: For unit testing.
- `colorama`: For colored terminal output.
- `py`: For Python path manipulation.
- `pluggy`: For plugin management in pytest.
- `iniconfig`: For parsing INI config files.
- `tomli`: For parsing TOML config files.
- `tzlocal`: For getting the local timezone.
- `argparse`: For parsing command-line arguments.
- `typing`: For type hints.
- `requests`: For making HTTP requests.

### Using the Database
The Intrusion Detection System (IDS) includes a database (`ids.db`) that stores alerts and other relevant data. You can interact with the database using SQL queries. Below are some examples of how to use the database:

#### Retrieve All Alerts
To retrieve all alerts stored in the `alerts` table, use the following query:
```sql
SELECT * FROM alerts;
```
Example command:
```bash
python -c "import sqlite3; conn = sqlite3.connect('ids.db'); cursor = conn.cursor(); cursor.execute('SELECT * FROM alerts'); print(cursor.fetchall())"
```

#### Filter Alerts by Protocol
To filter alerts by protocol (e.g., TCP), use the following query:
```sql
SELECT * FROM alerts WHERE protocol = 'TCP';
```
Example command:
```bash
python -c "import sqlite3; conn = sqlite3.connect('ids.db'); cursor = conn.cursor(); cursor.execute('SELECT * FROM alerts WHERE protocol = \'TCP\''); print(cursor.fetchall())"
```

#### Filter Alerts by Timestamp
To filter alerts within a specific time range, use the following query:
```sql
SELECT * FROM alerts WHERE timestamp BETWEEN '2025-08-06 19:00:00' AND '2025-08-06 19:01:00';
```
Example command:
```bash
python -c "import sqlite3; conn = sqlite3.connect('ids.db'); cursor = conn.cursor(); cursor.execute('SELECT * FROM alerts WHERE timestamp BETWEEN \'2025-08-06 19:00:00\' AND \'2025-08-06 19:01:00\''); print(cursor.fetchall())"
```

#### Insert a New Alert
To manually insert a new alert into the database, use the following query:
```sql
INSERT INTO alerts (timestamp, ip, protocol, alert_type, description, ports)
VALUES ('2025-08-06 19:30:00', '192.168.0.100', 'UDP', 'Port Scan', 'Possible UDP port scan detected', '53,5353,5355');
```

#### Update an Existing Alert
To update an existing alert, use the following query:
```sql
UPDATE alerts
SET description = 'Updated alert description'
WHERE id = 1;
```

#### Delete an Alert
To delete an alert from the database, use the following query:
```sql
DELETE FROM alerts WHERE id = 1;
```

These examples demonstrate how to interact with the `ids.db` database using SQL queries. You can use these queries to retrieve, filter, and analyze the data as needed.

## License
This project is licensed under the MIT License.
