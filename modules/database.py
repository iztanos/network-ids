import sqlite3
import datetime

def init_db():
    conn = sqlite3.connect("ids_logs.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            protocol TEXT,
            alert_type TEXT,
            description TEXT,
            ports TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_alert_to_db(ip, protocol, alert_type, description, ports):
    conn = sqlite3.connect("ids_logs.db")
    cursor = conn.cursor()

    timestamp = datetime.datetime.now().isoformat()
    ports_str = ", ".join(str(p) for p in ports) if isinstance(ports, (list, set)) else str(ports)

    cursor.execute('''
        INSERT INTO alerts (timestamp, ip, protocol, alert_type, description, ports)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, ip, protocol, alert_type, description, ports_str))

    conn.commit()
    conn.close()

def search_alerts_by_ip(ip_address):
    conn = sqlite3.connect("ids_logs.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE ip = ?", (ip_address,))
    results = cursor.fetchall()

    for row in results:
        print(row)

    conn.close()
