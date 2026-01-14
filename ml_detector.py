#!/usr/bin/env python3
"""
ML-based Anomaly Detection for Tandoori IDS
Uses Isolation Forest to detect unusual network traffic patterns.
"""

import sqlite3
import pickle
import os
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from config import DB_PATH

MODEL_PATH = "ids_model.pkl"
SCALER_PATH = "ids_scaler.pkl"

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.baseline_stats = {}
        self.traffic_buffer = defaultdict(lambda: {
            "packet_count": 0,
            "unique_dests": set(),
            "unique_ports": set(),
            "total_bytes": 0,
            "start_time": None
        })
        self.load_model()

    def load_model(self):
        """Load pre-trained model if exists."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("[ML] Loaded existing model")
                return True
            except Exception as e:
                print(f"[ML] Error loading model: {e}")
        return False

    def save_model(self):
        """Save trained model."""
        if self.model and self.scaler:
            with open(MODEL_PATH, 'wb') as f:
                pickle.dump(self.model, f)
            with open(SCALER_PATH, 'wb') as f:
                pickle.dump(self.scaler, f)
            print("[ML] Model saved")

    def extract_features_from_db(self, hours=24):
        """Extract training features from historical traffic data."""
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Get traffic aggregated by source IP per 5-minute window
        c.execute("""
            SELECT
                source_ip,
                strftime('%Y-%m-%d %H:%M', timestamp, 'start of minute', '-' || (strftime('%M', timestamp) % 5) || ' minutes') as window,
                COUNT(*) as packet_count,
                COUNT(DISTINCT dest_ip) as unique_dests,
                COUNT(DISTINCT port) as unique_ports,
                COALESCE(SUM(size), 0) as total_bytes,
                CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                CAST(strftime('%w', timestamp) AS INTEGER) as day_of_week
            FROM traffic_log
            WHERE timestamp > datetime('now', ?)
            GROUP BY source_ip, window
        """, (f'-{hours} hours',))

        results = c.fetchall()
        conn.close()

        if not results:
            return None

        # Convert to feature matrix
        features = []
        for row in results:
            src_ip, window, packet_count, unique_dests, unique_ports, total_bytes, hour, dow = row
            features.append([
                packet_count,
                unique_dests,
                unique_ports,
                total_bytes,
                hour,
                dow,
                # Derived features
                total_bytes / max(packet_count, 1),  # avg packet size
                unique_ports / max(unique_dests, 1),  # ports per dest ratio
            ])

        return np.array(features)

    def train(self, hours=24, contamination=0.05):
        """Train the Isolation Forest on historical data."""
        print(f"[ML] Training on last {hours} hours of traffic...")

        features = self.extract_features_from_db(hours)

        if features is None or len(features) < 10:
            print("[ML] Not enough data to train (need at least 10 samples)")
            return False

        # Scale features
        self.scaler = StandardScaler()
        features_scaled = self.scaler.fit_transform(features)

        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=contamination,  # Expected proportion of outliers
            n_estimators=100,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(features_scaled)

        # Calculate baseline statistics
        self.baseline_stats = {
            'mean_packets': np.mean(features[:, 0]),
            'std_packets': np.std(features[:, 0]),
            'mean_bytes': np.mean(features[:, 3]),
            'std_bytes': np.std(features[:, 3]),
            'samples_trained': len(features)
        }

        self.save_model()
        print(f"[ML] Trained on {len(features)} samples")
        print(f"[ML] Baseline: ~{self.baseline_stats['mean_packets']:.0f} packets, ~{self.baseline_stats['mean_bytes']:.0f} bytes per 5-min window")
        return True

    def record_packet(self, src_ip, dst_ip, port, size, protocol):
        """Record a packet for real-time analysis."""
        now = datetime.now()
        buf = self.traffic_buffer[src_ip]

        # Reset buffer every 5 minutes
        if buf["start_time"] is None or (now - buf["start_time"]).seconds >= 300:
            buf["packet_count"] = 0
            buf["unique_dests"] = set()
            buf["unique_ports"] = set()
            buf["total_bytes"] = 0
            buf["start_time"] = now

        buf["packet_count"] += 1
        buf["unique_dests"].add(dst_ip)
        buf["unique_ports"].add(port)
        buf["total_bytes"] += size or 0

    def check_anomaly(self, src_ip):
        """Check if current traffic from src_ip is anomalous."""
        if self.model is None or self.scaler is None:
            return None, 0

        buf = self.traffic_buffer[src_ip]
        if buf["packet_count"] < 5:  # Need minimum traffic
            return None, 0

        now = datetime.now()
        features = np.array([[
            buf["packet_count"],
            len(buf["unique_dests"]),
            len(buf["unique_ports"]),
            buf["total_bytes"],
            now.hour,
            now.weekday(),
            buf["total_bytes"] / max(buf["packet_count"], 1),
            len(buf["unique_ports"]) / max(len(buf["unique_dests"]), 1),
        ]])

        try:
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)[0]
            score = self.model.score_samples(features_scaled)[0]

            is_anomaly = prediction == -1
            return is_anomaly, score
        except Exception as e:
            print(f"[ML] Prediction error: {e}")
            return None, 0

    def get_anomaly_description(self, src_ip):
        """Get human-readable description of why traffic is anomalous."""
        buf = self.traffic_buffer[src_ip]
        now = datetime.now()

        reasons = []

        if self.baseline_stats:
            # Check packet count
            if buf["packet_count"] > self.baseline_stats['mean_packets'] + 3 * self.baseline_stats['std_packets']:
                reasons.append(f"high packet rate ({buf['packet_count']} vs avg {self.baseline_stats['mean_packets']:.0f})")

            # Check bytes
            if buf["total_bytes"] > self.baseline_stats['mean_bytes'] + 3 * self.baseline_stats['std_bytes']:
                reasons.append(f"high traffic volume ({buf['total_bytes']} bytes)")

        # Check unusual hour (late night/early morning for restaurant)
        if now.hour >= 2 and now.hour <= 5:
            reasons.append(f"unusual hour ({now.hour}:00)")

        # Check port scanning behavior
        if len(buf["unique_ports"]) > 20:
            reasons.append(f"many unique ports ({len(buf['unique_ports'])})")

        # Check many destinations
        if len(buf["unique_dests"]) > 10:
            reasons.append(f"many destinations ({len(buf['unique_dests'])})")

        return ", ".join(reasons) if reasons else "statistical anomaly"


# Singleton instance
detector = AnomalyDetector()

def train_model(hours=24):
    """Train the model on historical data."""
    return detector.train(hours)

def record_and_check(src_ip, dst_ip, port, size, protocol):
    """Record packet and check for anomalies. Returns (is_anomaly, score, description)."""
    detector.record_packet(src_ip, dst_ip, port, size, protocol)
    is_anomaly, score = detector.check_anomaly(src_ip)

    if is_anomaly:
        desc = detector.get_anomaly_description(src_ip)
        return True, score, desc

    return False, score, None


if __name__ == "__main__":
    print("Tandoori IDS - ML Anomaly Detector")
    print("-" * 40)

    # Train on available data
    if train_model(hours=24):
        print("\nModel trained successfully!")
        print(f"Baseline stats: {detector.baseline_stats}")
    else:
        print("\nNot enough data to train. Run the IDS to collect traffic first.")
