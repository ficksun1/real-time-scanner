import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from auth import DatabaseManager
from file_manager import FileManager

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def get_user_scan_history(user_id):
    """Get scan history for the user"""
    db = DatabaseManager()
    try:
        conn = db.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user details
        cursor.execute('SELECT username, email, created_at FROM users WHERE id = %s', (user_id,))
        user_info = cursor.fetchone()
        
        # Get scan history with vulnerability data
        cursor.execute('''
            SELECT pd.scan_timestamp, pd.scan_type, pd.ip_address, pd.status, 
                   pd.ports, pd.services, pd.os_info,
                   COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_vulns,
                   COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_vulns,
                   COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END) as medium_vulns,
                   COUNT(CASE WHEN v.severity = 'Low' THEN 1 END) as low_vulns
            FROM packet_data pd
            LEFT JOIN vulnerabilities v ON pd.id = v.scan_id
            WHERE pd.user_id = %s 
            GROUP BY pd.id
            ORDER BY pd.scan_timestamp DESC
        ''', (user_id,))
        scan_history = cursor.fetchall()
        
        cursor.close()
        conn.close()
        return user_info, scan_history
    except Exception as e:
        st.error(f"Error fetching user data: {str(e)}")
        return None, None

def create_scan_metrics(scan_history):
    """Create enhanced metrics from scan history"""
    if not scan_history:
        return {}
    
    total_scans = len(scan_history)
    scan_types = {}
    vulnerable_ports = 0
    unique_ips = set()
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    for scan in scan_history:
        scan_types[scan['scan_type']] = scan_types.get(scan['scan_type'], 0) + 1
        unique_ips.add(scan['ip_address'])
        if scan['ports']:
            vulnerable_ports += len(scan['ports'].split(','))
        
        # Add severity counts
        severity_counts['Critical'] += scan['critical_vulns']
        severity_counts['High'] += scan['high_vulns']
        severity_counts['Medium'] += scan['medium_vulns']
        severity_counts['Low'] += scan['low_vulns']
    
    return {
        'total_scans': total_scans,
        'unique_ips': len(unique_ips),
        'scan_types': scan_types,
        'vulnerable_ports': vulnerable_ports,
        'severity_counts': severity_counts
    }

def display_profile():
    init_style()
    
    if 'user_id' not in st.session_state:
        st.error("Please login to view profile")
        st.switch_page("login.py")
        return
    
    user_info, scan_history = get_user_scan_history(st.session_state.user_id)
    
    if not user_info:
        st.error("Could not fetch user information")
        return
    
    # User Profile Header with Cyberpunk styling
    st.markdown("""
        <div class="profile-header">
            <h1>Security Dashboard</h1>
            <div class="cyber-line"></div>
        </div>
    """, unsafe_allow_html=True)
    
    # User Information Card
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"""
        <div class="profile-card">
            <h3>Account Information</h3>
            <p><strong>Username:</strong> {user_info['username']}</p>
            <p><strong>Email:</strong> {user_info['email']}</p>
            <p><strong>Member Since:</strong> {user_info['created_at'].strftime('%B %d, %Y')}</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Enhanced Metrics with Severity
    metrics = create_scan_metrics(scan_history)
    if metrics:
        # Create two rows of metrics
        row1_cols = st.columns(4)
        with row1_cols[0]:
            st.metric("Total Scans", metrics['total_scans'])
        with row1_cols[1]:
            st.metric("Unique IPs", metrics['unique_ips'])
        with row1_cols[2]:
            st.metric("Vulnerable Ports", metrics['vulnerable_ports'])
        with row1_cols[3]:
            most_used_scan = max(metrics['scan_types'].items(), key=lambda x: x[1])[0]
            st.metric("Most Used Scan", most_used_scan)
        
        # Severity metrics
        st.subheader("Vulnerability Severity Distribution")
        severity_cols = st.columns(4)
        severity_colors = {
            'Critical': '#ff2a6d',
            'High': '#ff71ce',
            'Medium': '#05d9e8',
            'Low': '#00ff9f'
        }
        
        for i, (severity, count) in enumerate(metrics['severity_counts'].items()):
            with severity_cols[i]:
                st.markdown(f"""
                <div style="background: rgba(1, 1, 43, 0.7); padding: 1rem; border-radius: 10px; border: 1px solid {severity_colors[severity]}">
                    <h4 style="color: {severity_colors[severity]}">{severity}</h4>
                    <h2 style="color: {severity_colors[severity]}">{count}</h2>
                </div>
                """, unsafe_allow_html=True)
    
    # Scan History Graphs
    if scan_history:
        # Convert scan history to DataFrame
        df = pd.DataFrame(scan_history)
        df['scan_timestamp'] = pd.to_datetime(df['scan_timestamp'])
        
        # Create tabs for different visualizations
        tab1, tab2, tab3 = st.tabs(["Scan Activity", "Severity Analysis", "Protocol Distribution"])
        
        with tab1:
            # Enhanced Scan Activity Timeline
            st.subheader("Scan Activity Over Time")
            date_range = pd.date_range(
                start=df['scan_timestamp'].min().date(),
                end=df['scan_timestamp'].max().date()
            )
            daily_scans = df.groupby(df['scan_timestamp'].dt.date).size()
            daily_scans = daily_scans.reindex(date_range, fill_value=0)
            
            fig_timeline = go.Figure()
            fig_timeline.add_trace(go.Scatter(
                x=daily_scans.index,
                y=daily_scans.values,
                mode='lines+markers',
                name='Scans',
                line=dict(color="#ff2a6d", width=3),
                marker=dict(size=8, color="#05d9e8")
            ))
            
            fig_timeline.update_layout(
                template="plotly_dark",
                plot_bgcolor='rgba(1, 1, 43, 0.7)',
                paper_bgcolor='rgba(1, 1, 43, 0.7)',
                font=dict(family="Orbitron", color="#d1f7ff"),
                showlegend=False
            )
            
            st.plotly_chart(fig_timeline, use_container_width=True)
        
        with tab2:
            # Severity Distribution Over Time
            st.subheader("Vulnerability Severity Trends")
            severity_df = pd.DataFrame({
                'Date': df['scan_timestamp'].dt.date,
                'Critical': df['critical_vulns'],
                'High': df['high_vulns'],
                'Medium': df['medium_vulns'],
                'Low': df['low_vulns']
            })
            
            severity_df = severity_df.groupby('Date').sum()
            
            fig_severity = go.Figure()
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                fig_severity.add_trace(go.Scatter(
                    x=severity_df.index,
                    y=severity_df[severity],
                    name=severity,
                    stackgroup='one',
                    line=dict(width=0),
                    fillcolor=severity_colors[severity]
                ))
            
            fig_severity.update_layout(
                template="plotly_dark",
                plot_bgcolor='rgba(1, 1, 43, 0.7)',
                paper_bgcolor='rgba(1, 1, 43, 0.7)',
                font=dict(family="Orbitron", color="#d1f7ff")
            )
            
            st.plotly_chart(fig_severity, use_container_width=True)
        
        with tab3:
            # Protocol Distribution
            st.subheader("Protocol Distribution")
            protocols = df['scan_type'].value_counts()
            
            fig_protocols = go.Figure(data=[go.Pie(
                labels=protocols.index,
                values=protocols.values,
                hole=.3,
                marker=dict(colors=["#ff2a6d", "#05d9e8", "#ff71ce", "#00ff9f"])
            )])
            
            fig_protocols.update_layout(
                template="plotly_dark",
                plot_bgcolor='rgba(1, 1, 43, 0.7)',
                paper_bgcolor='rgba(1, 1, 43, 0.7)',
                font=dict(family="Orbitron", color="#d1f7ff")
            )
            
            st.plotly_chart(fig_protocols, use_container_width=True)
        
        # Recent Scans Table with Enhanced Styling
        st.subheader("Recent Scans")
        with st.expander("View Recent Scans", expanded=True):
            for scan in scan_history[:5]:
                severity_indicators = ""
                if scan['critical_vulns'] > 0:
                    severity_indicators += f"<span style='color: #ff2a6d'>⚠️ {scan['critical_vulns']} Critical</span> "
                if scan['high_vulns'] > 0:
                    severity_indicators += f"<span style='color: #ff71ce'>⚠️ {scan['high_vulns']} High</span> "
                
                st.markdown(f"""
                <div class="scan-card">
                    <h4>Scan on {scan['scan_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</h4>
                    <p><strong>IP Address:</strong> {scan['ip_address']}</p>
                    <p><strong>Scan Type:</strong> {scan['scan_type']}</p>
                    <p><strong>Status:</strong> {scan['status']}</p>
                    <p><strong>Ports:</strong> {scan['ports'] if scan['ports'] else 'None'}</p>
                    <p><strong>Vulnerabilities:</strong> {severity_indicators}</p>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No scan history available")

    # Report Generation Section
    st.subheader("Generate Reports")
    report_col1, report_col2, report_col3 = st.columns(3)
    
    with report_col1:
        if st.button("Generate Excel Report"):
            file_manager = FileManager(st.session_state.username)
            excel_path = file_manager.save_scan_excel(scan_history[-1] if scan_history else {}, "latest")
            st.success(f"Excel report generated: {excel_path}")
    
    with report_col2:
        if st.button("Generate Word Report"):
            file_manager = FileManager(st.session_state.username)
            word_path = file_manager.generate_user_report(scan_history)
            st.success(f"Word report generated: {word_path}")
    
    with report_col3:
        if st.button("Generate Network Monitor Report"):
            if 'packet_data' in st.session_state:
                file_manager = FileManager(st.session_state.username)
                doc = create_network_monitor_report(st.session_state['packet_data'])
                report_path = file_manager.save_report(doc, f"network_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                st.success(f"Network Monitor Report generated: {report_path}")
            else:
                st.warning("No network monitor data available")

    # Add to CSS
    st.markdown("""
    <style>
    .profile-card {
        background: rgba(1, 1, 43, 0.7);
        padding: 1.5rem;
        border-radius: 15px;
        border: 1px solid var(--primary-color);
        margin-bottom: 2rem;
    }
    .scan-card {
        background: rgba(1, 1, 43, 0.7);
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid var(--primary-color);
        margin-bottom: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    display_profile() 