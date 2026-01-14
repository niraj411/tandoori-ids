#!/usr/bin/env python3
"""
Tandoori IDS Dashboard
Real-time monitoring and visualization using Streamlit.
"""

import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import time
from config import DB_PATH, KNOWN_DEVICES

st.set_page_config(
    page_title="Tandoori IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
    }
    .alert-high { background-color: #ff4b4b; color: white; padding: 10px; border-radius: 5px; margin: 5px 0; }
    .alert-medium { background-color: #ffa500; color: white; padding: 10px; border-radius: 5px; margin: 5px 0; }
    .alert-low { background-color: #00cc00; color: white; padding: 10px; border-radius: 5px; margin: 5px 0; }
</style>
""", unsafe_allow_html=True)


def get_db_connection():
    return sqlite3.connect(DB_PATH)


@st.cache_data(ttl=5)
def get_alerts(limit=100):
    conn = get_db_connection()
    df = pd.read_sql_query(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
        conn, params=(limit,)
    )
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_devices():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_traffic_stats(minutes=60):
    conn = get_db_connection()
    df = pd.read_sql_query(f"""
        SELECT
            strftime('%Y-%m-%d %H:%M', timestamp) as minute,
            COUNT(*) as packets,
            SUM(size) as bytes,
            COUNT(DISTINCT source_ip) as unique_sources,
            COUNT(DISTINCT dest_ip) as unique_dests
        FROM traffic_log
        WHERE timestamp > datetime('now', '-{minutes} minutes')
        GROUP BY minute
        ORDER BY minute
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_top_talkers(minutes=60, limit=10):
    conn = get_db_connection()
    df = pd.read_sql_query(f"""
        SELECT
            source_ip,
            COUNT(*) as packets,
            SUM(size) as bytes,
            COUNT(DISTINCT dest_ip) as unique_dests,
            COUNT(DISTINCT port) as unique_ports
        FROM traffic_log
        WHERE timestamp > datetime('now', '-{minutes} minutes')
        GROUP BY source_ip
        ORDER BY packets DESC
        LIMIT ?
    """, conn, params=(limit,))
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_protocol_breakdown(minutes=60):
    conn = get_db_connection()
    df = pd.read_sql_query(f"""
        SELECT
            protocol,
            COUNT(*) as packets,
            SUM(size) as bytes
        FROM traffic_log
        WHERE timestamp > datetime('now', '-{minutes} minutes')
        GROUP BY protocol
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_alert_counts():
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT
            alert_type,
            severity,
            COUNT(*) as count
        FROM alerts
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY alert_type, severity
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_hourly_traffic():
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT
            strftime('%H', timestamp) as hour,
            COUNT(*) as packets,
            SUM(size) as bytes
        FROM traffic_log
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """, conn)
    conn.close()
    return df


def main():
    st.title("🛡️ Tandoori IDS Dashboard")
    st.caption("Real-time Network Intrusion Detection")

    # Sidebar
    with st.sidebar:
        st.header("Settings")
        auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
        time_window = st.selectbox("Time window", [15, 30, 60, 120, 360], index=2)
        st.divider()
        st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

        if st.button("🔄 Refresh Now"):
            st.cache_data.clear()
            st.rerun()

    # Top metrics row
    col1, col2, col3, col4 = st.columns(4)

    alerts_df = get_alerts(1000)
    devices_df = get_devices()
    traffic_df = get_traffic_stats(time_window)

    # Calculate metrics
    total_alerts_24h = len(alerts_df[alerts_df['timestamp'] > (datetime.now() - timedelta(hours=24)).isoformat()]) if not alerts_df.empty else 0
    high_severity = len(alerts_df[(alerts_df['severity'] == 'high') & (alerts_df['timestamp'] > (datetime.now() - timedelta(hours=24)).isoformat())]) if not alerts_df.empty else 0
    total_devices = len(devices_df) if not devices_df.empty else 0
    total_packets = traffic_df['packets'].sum() if not traffic_df.empty else 0

    with col1:
        st.metric("Alerts (24h)", total_alerts_24h, delta=None)
    with col2:
        st.metric("High Severity", high_severity, delta=None, delta_color="inverse")
    with col3:
        st.metric("Devices Seen", total_devices)
    with col4:
        st.metric(f"Packets ({time_window}m)", f"{total_packets:,}")

    st.divider()

    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Traffic", "🚨 Alerts", "💻 Devices", "🔬 Analysis"])

    # Traffic Tab
    with tab1:
        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("Traffic Over Time")
            if not traffic_df.empty:
                st.line_chart(traffic_df.set_index('minute')[['packets']], use_container_width=True)
            else:
                st.info("No traffic data available yet. Start the IDS to collect data.")

        with col2:
            st.subheader("Protocol Breakdown")
            protocol_df = get_protocol_breakdown(time_window)
            if not protocol_df.empty:
                st.bar_chart(protocol_df.set_index('protocol')[['packets']])
            else:
                st.info("No protocol data yet.")

        st.subheader("Top Talkers")
        top_talkers = get_top_talkers(time_window)
        if not top_talkers.empty:
            # Add device names if known
            def get_device_name(ip):
                for mac, name in KNOWN_DEVICES.items():
                    pass  # We'd need MAC to IP mapping
                return ip

            st.dataframe(
                top_talkers,
                column_config={
                    "source_ip": "Source IP",
                    "packets": st.column_config.NumberColumn("Packets", format="%d"),
                    "bytes": st.column_config.NumberColumn("Bytes", format="%d"),
                    "unique_dests": "Unique Destinations",
                    "unique_ports": "Unique Ports"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No traffic data yet.")

    # Alerts Tab
    with tab2:
        st.subheader("Recent Alerts")

        # Alert filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium"])
        with col2:
            type_filter = st.multiselect("Type", alerts_df['alert_type'].unique().tolist() if not alerts_df.empty else [])

        filtered_alerts = alerts_df.copy()
        if severity_filter:
            filtered_alerts = filtered_alerts[filtered_alerts['severity'].isin(severity_filter)]
        if type_filter:
            filtered_alerts = filtered_alerts[filtered_alerts['alert_type'].isin(type_filter)]

        if not filtered_alerts.empty:
            for _, alert in filtered_alerts.head(50).iterrows():
                severity_class = f"alert-{alert['severity']}"
                icon = "🔴" if alert['severity'] == 'high' else "🟠" if alert['severity'] == 'medium' else "🟢"
                st.markdown(f"""
                <div class="{severity_class}">
                    {icon} <strong>[{alert['alert_type']}]</strong> {alert['details']}<br>
                    <small>{alert['timestamp']} | Source: {alert['source_ip']}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("No alerts matching filters. Network looks healthy!")

        # Alert statistics
        st.subheader("Alert Statistics (24h)")
        alert_counts = get_alert_counts()
        if not alert_counts.empty:
            col1, col2 = st.columns(2)
            with col1:
                st.bar_chart(alert_counts.groupby('alert_type')['count'].sum())
            with col2:
                st.bar_chart(alert_counts.groupby('severity')['count'].sum())

    # Devices Tab
    with tab3:
        st.subheader("Device Inventory")

        if not devices_df.empty:
            # Enrich with known device names
            def enrich_device(row):
                mac = row['mac'].lower()
                for known_mac, name in KNOWN_DEVICES.items():
                    if known_mac.lower() == mac:
                        return name
                return row.get('name', 'Unknown')

            devices_df['device_name'] = devices_df.apply(enrich_device, axis=1)

            # Show known vs unknown
            known_count = len(devices_df[devices_df['device_name'] != 'Unknown'])
            unknown_count = len(devices_df[devices_df['device_name'] == 'Unknown'])

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Known Devices", known_count)
            with col2:
                st.metric("Unknown Devices", unknown_count, delta_color="inverse")

            # Device table
            st.dataframe(
                devices_df[['mac', 'ip', 'device_name', 'first_seen', 'last_seen']],
                column_config={
                    "mac": "MAC Address",
                    "ip": "IP Address",
                    "device_name": "Device Name",
                    "first_seen": "First Seen",
                    "last_seen": "Last Seen"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No devices discovered yet. Start the IDS to detect devices.")

    # Analysis Tab
    with tab4:
        st.subheader("Network Health Analysis")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Traffic by Hour (24h)")
            hourly = get_hourly_traffic()
            if not hourly.empty:
                st.bar_chart(hourly.set_index('hour')[['packets']])
            else:
                st.info("Not enough data for hourly analysis.")

        with col2:
            st.markdown("### Health Indicators")

            # Calculate health metrics
            if not alerts_df.empty and not traffic_df.empty:
                recent_high_alerts = len(alerts_df[(alerts_df['severity'] == 'high') &
                                                   (alerts_df['timestamp'] > (datetime.now() - timedelta(hours=1)).isoformat())])

                if recent_high_alerts == 0:
                    st.success("✅ No high-severity alerts in the last hour")
                elif recent_high_alerts < 5:
                    st.warning(f"⚠️ {recent_high_alerts} high-severity alerts in the last hour")
                else:
                    st.error(f"🚨 {recent_high_alerts} high-severity alerts in the last hour!")

                # Check for ML anomalies
                ml_anomalies = len(alerts_df[(alerts_df['alert_type'] == 'ml_anomaly') &
                                              (alerts_df['timestamp'] > (datetime.now() - timedelta(hours=1)).isoformat())])
                if ml_anomalies > 0:
                    st.warning(f"🤖 {ml_anomalies} ML-detected anomalies in the last hour")
                else:
                    st.success("✅ No ML anomalies detected")

                # Unknown devices
                if not devices_df.empty:
                    recent_unknown = len(alerts_df[(alerts_df['alert_type'] == 'rogue_device') &
                                                   (alerts_df['timestamp'] > (datetime.now() - timedelta(hours=24)).isoformat())])
                    if recent_unknown > 0:
                        st.warning(f"📱 {recent_unknown} new unknown devices in 24h")
                    else:
                        st.success("✅ No new unknown devices")
            else:
                st.info("Collecting data for health analysis...")

        st.markdown("### ML Model Status")
        import os
        if os.path.exists("ids_model.pkl"):
            st.success("✅ ML anomaly detection model is trained and active")
            try:
                from ml_detector import detector
                if detector.baseline_stats:
                    st.json(detector.baseline_stats)
            except:
                pass
        else:
            st.warning("⚠️ ML model not trained yet. Run: `python ml_detector.py`")

    # Auto-refresh
    if auto_refresh:
        time.sleep(5)
        st.cache_data.clear()
        st.rerun()


if __name__ == "__main__":
    main()
