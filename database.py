import sqlite3
import threading
import queue
from datetime import datetime
from config import DB_PATH

# Write queue for batching DB operations
write_queue = queue.Queue()
db_lock = threading.Lock()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        alert_type TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        details TEXT,
        severity TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        first_seen TEXT,
        last_seen TEXT,
        ip TEXT,
        known INTEGER DEFAULT 0,
        name TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        protocol TEXT,
        port INTEGER,
        size INTEGER
    )''')
    
    conn.commit()
    conn.close()

def log_alert(alert_type, source_ip, dest_ip, details, severity="medium"):
    try:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO alerts (timestamp, alert_type, source_ip, dest_ip, details, severity) VALUES (?, ?, ?, ?, ?, ?)",
                      (datetime.now().isoformat(), alert_type, source_ip, dest_ip, details, severity))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[DB] Error logging alert: {e}")

def log_device(mac, ip):
    try:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            now = datetime.now().isoformat()
            c.execute("INSERT OR REPLACE INTO devices (mac, first_seen, last_seen, ip, known, name) VALUES (?, COALESCE((SELECT first_seen FROM devices WHERE mac = ?), ?), ?, ?, (SELECT known FROM devices WHERE mac = ?), (SELECT name FROM devices WHERE mac = ?))",
                      (mac, mac, now, now, ip, mac, mac))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[DB] Error logging device: {e}")

# Traffic buffer for batch inserts
traffic_buffer = []
traffic_buffer_lock = threading.Lock()

def log_traffic(source_ip, dest_ip, protocol, port, size):
    """Log traffic for ML analysis (buffered)."""
    with traffic_buffer_lock:
        traffic_buffer.append((datetime.now().isoformat(), source_ip, dest_ip, protocol, port, size))

        # Batch insert every 100 packets
        if len(traffic_buffer) >= 100:
            flush_traffic_buffer()

def flush_traffic_buffer():
    """Write buffered traffic to database."""
    global traffic_buffer
    with traffic_buffer_lock:
        if not traffic_buffer:
            return
        batch = traffic_buffer.copy()
        traffic_buffer = []

    try:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.executemany("INSERT INTO traffic_log (timestamp, source_ip, dest_ip, protocol, port, size) VALUES (?, ?, ?, ?, ?, ?)", batch)
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[DB] Error flushing traffic: {e}")

def get_traffic_stats(minutes=60):
    """Get traffic statistics for the last N minutes."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT
            source_ip,
            COUNT(*) as packet_count,
            COUNT(DISTINCT dest_ip) as unique_dests,
            COUNT(DISTINCT port) as unique_ports,
            SUM(size) as total_bytes,
            strftime('%H', timestamp) as hour
        FROM traffic_log
        WHERE timestamp > datetime('now', ?)
        GROUP BY source_ip
    """, (f'-{minutes} minutes',))
    results = c.fetchall()
    conn.close()
    return results

def get_alerts(limit=100):
    """Get recent alerts."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    results = c.fetchall()
    conn.close()
    return results

def get_devices():
    """Get all known devices."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    results = c.fetchall()
    conn.close()
    return results

def get_traffic_timeseries(minutes=60):
    """Get traffic counts per minute for graphing."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT
            strftime('%Y-%m-%d %H:%M', timestamp) as minute,
            COUNT(*) as packets,
            SUM(size) as bytes
        FROM traffic_log
        WHERE timestamp > datetime('now', ?)
        GROUP BY minute
        ORDER BY minute
    """, (f'-{minutes} minutes',))
    results = c.fetchall()
    conn.close()
    return results

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
