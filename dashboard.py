#!/usr/bin/env python3
"""
Tandoori IDS Dashboard
Real-time monitoring and visualization using Streamlit.
Features: Interactive charts, scatter plots, heatmaps, network graphs.
"""

import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
from datetime import datetime, timedelta
import time

# Visualization libraries
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx

from config import DB_PATH, KNOWN_DEVICES

# Configure page
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
    .stPlotlyChart { background-color: transparent; }
</style>
""", unsafe_allow_html=True)

# Set plot styles
plt.style.use('dark_background')
sns.set_theme(style="darkgrid")


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
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='ISO8601')
    return df


@st.cache_data(ttl=5)
def get_devices():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_traffic_data(minutes=60):
    conn = get_db_connection()
    df = pd.read_sql_query(f"""
        SELECT * FROM traffic_log
        WHERE timestamp > datetime('now', '-{minutes} minutes')
        ORDER BY timestamp
    """, conn)
    conn.close()
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='ISO8601')
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
def get_port_stats(minutes=60):
    conn = get_db_connection()
    df = pd.read_sql_query(f"""
        SELECT
            port,
            protocol,
            COUNT(*) as count
        FROM traffic_log
        WHERE timestamp > datetime('now', '-{minutes} minutes')
        GROUP BY port, protocol
        ORDER BY count DESC
        LIMIT 20
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_connections(minutes=60):
    """Get source-destination pairs for network graph."""
    conn = get_db_connection()
    df = pd.read_sql_query(f"""
        SELECT
            source_ip,
            dest_ip,
            COUNT(*) as weight,
            SUM(size) as bytes
        FROM traffic_log
        WHERE timestamp > datetime('now', '-{minutes} minutes')
        GROUP BY source_ip, dest_ip
        ORDER BY weight DESC
        LIMIT 50
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def get_hourly_heatmap_data():
    """Get data for day/hour heatmap."""
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT
            CAST(strftime('%w', timestamp) AS INTEGER) as day_of_week,
            CAST(strftime('%H', timestamp) AS INTEGER) as hour,
            COUNT(*) as packets
        FROM traffic_log
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY day_of_week, hour
    """, conn)
    conn.close()
    return df


def create_traffic_scatter(df):
    """Create scatter plot of packet sizes vs time."""
    if df.empty:
        return None

    fig = px.scatter(
        df,
        x='timestamp',
        y='size',
        color='protocol',
        size='size',
        hover_data=['source_ip', 'dest_ip', 'port'],
        title='Packet Size Distribution Over Time',
        labels={'size': 'Packet Size (bytes)', 'timestamp': 'Time'},
        color_discrete_map={'TCP': '#00d4ff', 'UDP': '#ff6b6b'}
    )
    fig.update_layout(
        template='plotly_dark',
        height=400,
        showlegend=True
    )
    return fig


def create_port_scatter(df):
    """Create scatter plot of ports vs packet count."""
    if df.empty:
        return None

    fig = px.scatter(
        df,
        x='port',
        y='count',
        size='count',
        color='protocol',
        hover_name='port',
        title='Port Activity Distribution',
        labels={'count': 'Packet Count', 'port': 'Port Number'},
        color_discrete_map={'TCP': '#00d4ff', 'UDP': '#ff6b6b'}
    )
    fig.update_layout(template='plotly_dark', height=400)
    return fig


def create_network_graph(connections_df):
    """Create network topology visualization."""
    if connections_df.empty:
        return None

    G = nx.DiGraph()

    for _, row in connections_df.iterrows():
        G.add_edge(row['source_ip'], row['dest_ip'], weight=row['weight'])

    pos = nx.spring_layout(G, k=2, iterations=50)

    # Create edge traces
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    # Create node traces
    node_x, node_y, node_text, node_size = [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        # Size based on connections
        node_size.append(10 + G.degree(node) * 3)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="top center",
        textfont=dict(size=8, color='white'),
        marker=dict(
            showscale=True,
            colorscale='Viridis',
            size=node_size,
            color=[G.degree(n) for n in G.nodes()],
            colorbar=dict(title='Connections'),
            line_width=2
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='Network Connection Graph',
                        showlegend=False,
                        hovermode='closest',
                        template='plotly_dark',
                        height=500,
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    return fig


def create_heatmap(heatmap_df):
    """Create day/hour activity heatmap using seaborn."""
    if heatmap_df.empty:
        return None

    # Pivot for heatmap
    pivot = heatmap_df.pivot_table(
        index='day_of_week',
        columns='hour',
        values='packets',
        fill_value=0
    )

    # Reindex to ensure all days/hours present
    days = list(range(7))
    hours = list(range(24))
    pivot = pivot.reindex(index=days, columns=hours, fill_value=0)

    fig, ax = plt.subplots(figsize=(12, 4))
    sns.heatmap(
        pivot,
        cmap='YlOrRd',
        ax=ax,
        cbar_kws={'label': 'Packets'},
        xticklabels=[f'{h:02d}' for h in hours],
        yticklabels=['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    )
    ax.set_title('Traffic Heatmap (Last 7 Days)')
    ax.set_xlabel('Hour of Day')
    ax.set_ylabel('Day of Week')
    plt.tight_layout()
    return fig


def create_alert_timeline(alerts_df):
    """Create timeline of alerts."""
    if alerts_df.empty:
        return None

    # Color map for severity
    color_map = {'high': '#ff4b4b', 'medium': '#ffa500', 'low': '#00cc00'}

    fig = px.scatter(
        alerts_df,
        x='timestamp',
        y='alert_type',
        color='severity',
        size_max=15,
        hover_data=['source_ip', 'details'],
        title='Alert Timeline',
        color_discrete_map=color_map
    )
    fig.update_traces(marker=dict(size=12, symbol='diamond'))
    fig.update_layout(template='plotly_dark', height=300)
    return fig


def create_traffic_gauge(current_rate, avg_rate):
    """Create gauge chart for current traffic rate."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=current_rate,
        delta={'reference': avg_rate, 'relative': True},
        title={'text': "Packets/min"},
        gauge={
            'axis': {'range': [0, max(avg_rate * 3, current_rate * 1.5)]},
            'bar': {'color': "#00d4ff"},
            'steps': [
                {'range': [0, avg_rate], 'color': "#1a1a2e"},
                {'range': [avg_rate, avg_rate * 2], 'color': "#16213e"},
                {'range': [avg_rate * 2, avg_rate * 3], 'color': "#e94560"}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.75,
                'value': avg_rate
            }
        }
    ))
    fig.update_layout(template='plotly_dark', height=250)
    return fig


def create_protocol_pie(traffic_df):
    """Create pie chart of protocol distribution."""
    if traffic_df.empty:
        return None

    protocol_counts = traffic_df['protocol'].value_counts()

    fig = go.Figure(data=[go.Pie(
        labels=protocol_counts.index,
        values=protocol_counts.values,
        hole=0.4,
        marker_colors=['#00d4ff', '#ff6b6b', '#ffd93d']
    )])
    fig.update_layout(
        title='Protocol Distribution',
        template='plotly_dark',
        height=300
    )
    return fig


def create_bytes_area_chart(stats_df):
    """Create area chart of traffic volume."""
    if stats_df.empty:
        return None

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=stats_df['minute'],
        y=stats_df['bytes'],
        fill='tozeroy',
        fillcolor='rgba(0, 212, 255, 0.3)',
        line=dict(color='#00d4ff', width=2),
        name='Bytes'
    ))
    fig.update_layout(
        title='Traffic Volume Over Time',
        template='plotly_dark',
        height=300,
        xaxis_title='Time',
        yaxis_title='Bytes'
    )
    return fig


def main():
    st.title("🛡️ Tandoori IDS Dashboard")
    st.caption("Real-time Network Intrusion Detection with ML Anomaly Detection")

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        auto_refresh = st.checkbox("Auto-refresh (10s)", value=False)
        time_window = st.selectbox("Time window (minutes)", [15, 30, 60, 120, 360], index=2)

        st.divider()

        st.header("📊 Visualization")
        show_scatter = st.checkbox("Show Scatter Plots", value=True)
        show_network = st.checkbox("Show Network Graph", value=True)
        show_heatmap = st.checkbox("Show Heatmap", value=True)

        st.divider()
        st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

        if st.button("🔄 Refresh Now"):
            st.cache_data.clear()
            st.rerun()

    # Load data
    alerts_df = get_alerts(1000)
    devices_df = get_devices()
    traffic_df = get_traffic_data(time_window)
    stats_df = get_traffic_stats(time_window)

    # Top metrics row
    col1, col2, col3, col4, col5 = st.columns(5)

    total_alerts_24h = len(alerts_df[alerts_df['timestamp'] > (datetime.now() - timedelta(hours=24))]) if not alerts_df.empty else 0
    high_severity = len(alerts_df[(alerts_df['severity'] == 'high') & (alerts_df['timestamp'] > (datetime.now() - timedelta(hours=24)))]) if not alerts_df.empty else 0
    total_devices = len(devices_df) if not devices_df.empty else 0
    total_packets = len(traffic_df) if not traffic_df.empty else 0
    total_bytes = traffic_df['size'].sum() if not traffic_df.empty else 0

    with col1:
        st.metric("🚨 Alerts (24h)", total_alerts_24h)
    with col2:
        st.metric("⚠️ High Severity", high_severity, delta_color="inverse")
    with col3:
        st.metric("💻 Devices", total_devices)
    with col4:
        st.metric("📦 Packets", f"{total_packets:,}")
    with col5:
        st.metric("📊 Data", f"{total_bytes / 1024 / 1024:.1f} MB")

    st.divider()

    # Main tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📈 Traffic", "🔬 Analysis", "🚨 Alerts", "💻 Devices", "🗺️ Network"])

    # Traffic Tab
    with tab1:
        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("Traffic Over Time")
            if not stats_df.empty:
                fig = create_bytes_area_chart(stats_df)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No traffic data available. Start the IDS to collect data.")

        with col2:
            st.subheader("Protocol Mix")
            if not traffic_df.empty:
                fig = create_protocol_pie(traffic_df)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)

        # Scatter plot
        if show_scatter and not traffic_df.empty:
            st.subheader("📊 Packet Size Distribution")
            fig = create_traffic_scatter(traffic_df.tail(500))  # Last 500 for performance
            if fig:
                st.plotly_chart(fig, use_container_width=True)

        # Top talkers
        st.subheader("🔝 Top Talkers")
        top_talkers = get_top_talkers(time_window)
        if not top_talkers.empty:
            col1, col2 = st.columns([1, 1])
            with col1:
                st.dataframe(top_talkers, use_container_width=True, hide_index=True)
            with col2:
                fig = px.bar(
                    top_talkers.head(10),
                    x='source_ip',
                    y='packets',
                    color='bytes',
                    title='Top 10 Sources by Packet Count',
                    color_continuous_scale='Viridis'
                )
                fig.update_layout(template='plotly_dark', height=300)
                st.plotly_chart(fig, use_container_width=True)

    # Analysis Tab
    with tab2:
        st.subheader("🔬 Deep Analysis")

        col1, col2 = st.columns(2)

        with col1:
            # Port scatter
            port_stats = get_port_stats(time_window)
            if not port_stats.empty:
                fig = create_port_scatter(port_stats)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)

        with col2:
            # Traffic gauge
            if not stats_df.empty:
                current_rate = stats_df['packets'].iloc[-1] if len(stats_df) > 0 else 0
                avg_rate = stats_df['packets'].mean()
                fig = create_traffic_gauge(current_rate, avg_rate)
                st.plotly_chart(fig, use_container_width=True)

        # Heatmap
        if show_heatmap:
            st.subheader("🗓️ Weekly Traffic Pattern")
            heatmap_data = get_hourly_heatmap_data()
            if not heatmap_data.empty:
                fig = create_heatmap(heatmap_data)
                if fig:
                    st.pyplot(fig)
                plt.close()
            else:
                st.info("Need more data for heatmap (collecting over 7 days)")

        # Correlation matrix
        if not traffic_df.empty and len(traffic_df) > 10:
            st.subheader("📊 Feature Correlation")
            # Create numeric features
            traffic_df['hour'] = traffic_df['timestamp'].dt.hour
            traffic_df['minute'] = traffic_df['timestamp'].dt.minute
            traffic_df['port_category'] = pd.cut(traffic_df['port'], bins=[0, 1024, 49151, 65535], labels=['Well-known', 'Registered', 'Dynamic'])

            numeric_cols = ['size', 'port', 'hour']
            corr_matrix = traffic_df[numeric_cols].corr()

            fig, ax = plt.subplots(figsize=(8, 6))
            sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0, ax=ax, fmt='.2f')
            ax.set_title('Feature Correlation Matrix')
            st.pyplot(fig)
            plt.close()

    # Alerts Tab
    with tab3:
        st.subheader("🚨 Alert Timeline")

        if not alerts_df.empty:
            fig = create_alert_timeline(alerts_df.head(100))
            if fig:
                st.plotly_chart(fig, use_container_width=True)

            # Filters
            col1, col2 = st.columns(2)
            with col1:
                severity_filter = st.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium"])
            with col2:
                type_filter = st.multiselect("Type", alerts_df['alert_type'].unique().tolist())

            filtered = alerts_df.copy()
            if severity_filter:
                filtered = filtered[filtered['severity'].isin(severity_filter)]
            if type_filter:
                filtered = filtered[filtered['alert_type'].isin(type_filter)]

            # Alert cards
            for _, alert in filtered.head(20).iterrows():
                icon = "🔴" if alert['severity'] == 'high' else "🟠" if alert['severity'] == 'medium' else "🟢"
                st.markdown(f"""
                <div class="alert-{alert['severity']}">
                    {icon} <strong>[{alert['alert_type']}]</strong> {alert['details']}<br>
                    <small>{alert['timestamp']} | Source: {alert['source_ip']}</small>
                </div>
                """, unsafe_allow_html=True)

            # Alert type breakdown
            st.subheader("📊 Alert Breakdown")
            col1, col2 = st.columns(2)
            with col1:
                type_counts = alerts_df['alert_type'].value_counts()
                fig = px.pie(values=type_counts.values, names=type_counts.index, title='By Type', hole=0.4)
                fig.update_layout(template='plotly_dark', height=300)
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                sev_counts = alerts_df['severity'].value_counts()
                fig = px.pie(values=sev_counts.values, names=sev_counts.index, title='By Severity',
                           color=sev_counts.index, color_discrete_map={'high': '#ff4b4b', 'medium': '#ffa500', 'low': '#00cc00'},
                           hole=0.4)
                fig.update_layout(template='plotly_dark', height=300)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("No alerts! Network looks healthy.")

    # Devices Tab
    with tab4:
        st.subheader("💻 Device Inventory")

        if not devices_df.empty:
            def get_device_name(mac):
                mac_lower = mac.lower()
                for known_mac, name in KNOWN_DEVICES.items():
                    if known_mac.lower() == mac_lower:
                        return name
                return "Unknown"

            devices_df['device_name'] = devices_df['mac'].apply(get_device_name)
            devices_df['status'] = devices_df['device_name'].apply(lambda x: '✅ Known' if x != 'Unknown' else '⚠️ Unknown')

            known_count = len(devices_df[devices_df['device_name'] != 'Unknown'])
            unknown_count = len(devices_df[devices_df['device_name'] == 'Unknown'])

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Devices", len(devices_df))
            with col2:
                st.metric("Known", known_count)
            with col3:
                st.metric("Unknown", unknown_count, delta_color="inverse")

            # Device pie chart
            fig = go.Figure(data=[go.Pie(
                labels=['Known', 'Unknown'],
                values=[known_count, unknown_count],
                marker_colors=['#00cc00', '#ff4b4b'],
                hole=0.5
            )])
            fig.update_layout(title='Device Status', template='plotly_dark', height=300)
            st.plotly_chart(fig, use_container_width=True)

            st.dataframe(
                devices_df[['mac', 'ip', 'device_name', 'status', 'first_seen', 'last_seen']],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No devices discovered yet.")

    # Network Tab
    with tab5:
        st.subheader("🗺️ Network Topology")

        if show_network:
            connections = get_connections(time_window)
            if not connections.empty:
                fig = create_network_graph(connections)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)

                st.subheader("📋 Connection Table")
                st.dataframe(connections, use_container_width=True, hide_index=True)
            else:
                st.info("No connection data available.")

        # ML Model Status
        st.subheader("🤖 ML Model Status")
        import os
        if os.path.exists("ids_model.pkl"):
            st.success("Isolation Forest model is trained and active")
            try:
                from ml_detector import detector
                if detector.baseline_stats:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Avg Packets/5min", f"{detector.baseline_stats.get('mean_packets', 0):.0f}")
                    with col2:
                        st.metric("Avg Bytes/5min", f"{detector.baseline_stats.get('mean_bytes', 0):.0f}")
                    with col3:
                        st.metric("Training Samples", detector.baseline_stats.get('samples_trained', 0))
            except Exception as e:
                st.warning(f"Could not load model stats: {e}")
        else:
            st.warning("ML model not trained. Run: `python ml_detector.py`")

    # Auto-refresh
    if auto_refresh:
        time.sleep(10)
        st.cache_data.clear()
        st.rerun()


if __name__ == "__main__":
    main()
