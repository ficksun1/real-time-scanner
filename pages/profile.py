import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from auth import DatabaseManager

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
        
        # Get scan history
        cursor.execute('''
            SELECT scan_timestamp, scan_type, ip_address, status, 
                   ports, services, os_info 
            FROM packet_data 
            WHERE user_id = %s 
            ORDER BY scan_timestamp DESC
        ''', (user_id,))
        scan_history = cursor.fetchall()
        
        cursor.close()
        conn.close()
        return user_info, scan_history
    except Exception as e:
        st.error(f"Error fetching user data: {str(e)}")
        return None, None

def create_scan_metrics(scan_history):
    """Create metrics from scan history"""
    if not scan_history:
        return {}
    
    total_scans = len(scan_history)
    scan_types = {}
    vulnerable_ports = 0
    unique_ips = set()
    
    for scan in scan_history:
        scan_types[scan['scan_type']] = scan_types.get(scan['scan_type'], 0) + 1
        unique_ips.add(scan['ip_address'])
        if scan['ports']:
            vulnerable_ports += len(scan['ports'].split(','))
    
    return {
        'total_scans': total_scans,
        'unique_ips': len(unique_ips),
        'scan_types': scan_types,
        'vulnerable_ports': vulnerable_ports
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
    
    # User Profile Header
    st.markdown("""
        <div class="profile-header">
            <h1>User Profile</h1>
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
    
    # Scan Metrics
    metrics = create_scan_metrics(scan_history)
    if metrics:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Scans", metrics['total_scans'])
        with col2:
            st.metric("Unique IPs Scanned", metrics['unique_ips'])
        with col3:
            st.metric("Vulnerable Ports Found", metrics['vulnerable_ports'])
        with col4:
            most_used_scan = max(metrics['scan_types'].items(), key=lambda x: x[1])[0]
            st.metric("Most Used Scan", most_used_scan)
    
    # Scan History Graphs
    if scan_history:
        # Convert scan history to DataFrame
        df = pd.DataFrame(scan_history)
        df['scan_timestamp'] = pd.to_datetime(df['scan_timestamp'])
        
        # Scans Over Time
        st.subheader("Scan Activity Over Time")
        
        # Create date range for x-axis
        if len(df) > 0:
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
                title="Daily Scan Activity",
                template="plotly_dark",
                plot_bgcolor='rgba(1, 1, 43, 0.7)',
                paper_bgcolor='rgba(1, 1, 43, 0.7)',
                font=dict(family="Orbitron", color="#d1f7ff"),
                title_font=dict(family="Orbitron", color="#ff2a6d", size=24),
                showlegend=False,
                xaxis=dict(
                    title="Date",
                    showgrid=True,
                    gridcolor='rgba(5, 217, 232, 0.2)',
                    linecolor='rgba(5, 217, 232, 0.2)',
                    tickformat='%Y-%m-%d'
                ),
                yaxis=dict(
                    title="Number of Scans",
                    showgrid=True,
                    gridcolor='rgba(5, 217, 232, 0.2)',
                    linecolor='rgba(5, 217, 232, 0.2)',
                    tickmode='linear',
                    tick0=0,
                    dtick=1
                ),
                margin=dict(t=50, b=50, l=50, r=50),
                height=400
            )
            
            st.plotly_chart(fig_timeline, use_container_width=True)
            
            # Scan Types Distribution
            scan_type_counts = df['scan_type'].value_counts()
            fig_types = go.Figure(data=[go.Pie(
                labels=scan_type_counts.index,
                values=scan_type_counts.values,
                hole=.3,
                marker=dict(colors=["#ff2a6d", "#05d9e8", "#ff71ce", "#00ff9f"])
            )])
            
            fig_types.update_layout(
                title="Scan Types Distribution",
                template="plotly_dark",
                plot_bgcolor='rgba(1, 1, 43, 0.7)',
                paper_bgcolor='rgba(1, 1, 43, 0.7)',
                font=dict(family="Orbitron", color="#d1f7ff"),
                title_font=dict(family="Orbitron", color="#ff2a6d", size=24),
                showlegend=True,
                legend=dict(
                    font=dict(family="Orbitron", color="#d1f7ff"),
                    bgcolor='rgba(1, 1, 43, 0.7)',
                    bordercolor='rgba(5, 217, 232, 0.2)'
                ),
                margin=dict(t=50, b=50, l=50, r=50),
                height=400
            )
            
            st.plotly_chart(fig_types, use_container_width=True)
        else:
            st.info("No scan data available for visualization")
        
        # Recent Scans Table
        st.subheader("Recent Scans")
        with st.expander("View Recent Scans", expanded=True):
            for scan in scan_history[:5]:  # Show last 5 scans
                st.markdown(f"""
                <div class="scan-card">
                    <h4>Scan on {scan['scan_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</h4>
                    <p><strong>IP Address:</strong> {scan['ip_address']}</p>
                    <p><strong>Scan Type:</strong> {scan['scan_type']}</p>
                    <p><strong>Status:</strong> {scan['status']}</p>
                    <p><strong>Ports:</strong> {scan['ports'] if scan['ports'] else 'None'}</p>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No scan history available")

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