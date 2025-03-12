import streamlit as st
import pandas as pd
import plotly.express as px
import os

# Sample User Info
def get_user_info():
    return {"name": "John Doe", "email": "john.doe@example.com", "profile_pic": "https://via.placeholder.com/150"}

# Sample Scan Data
def get_scan_data():
    return pd.DataFrame([
        {"timestamp": "2025-03-12 10:00", "ip": "192.168.1.1", "scan_type": "Network Monitor", "status": "Success"},
        {"timestamp": "2025-03-12 10:30", "ip": "192.168.1.2", "scan_type": "Scanner Page", "status": "Failed"},
        {"timestamp": "2025-03-12 11:00", "ip": "192.168.1.3", "scan_type": "Network Monitor", "status": "Success"},
    ])

# UI Layout
st.title("Profile Page")

# User Info
user = get_user_info()
st.image(user["profile_pic"], width=100)
st.subheader(user["name"])
st.write(f"**Email:** {user['email']}")

# Scan Info
scan_data = get_scan_data()
total_scans = len(scan_data)
unique_ips = scan_data['ip'].nunique()
most_used_page = scan_data['scan_type'].value_counts().idxmax()

st.subheader("Scan Statistics")
st.write(f"**Total Scans:** {total_scans}")
st.write(f"**Unique IPs:** {unique_ips}")
st.write(f"**Most Used Page:** {most_used_page}")

# Scan Graph
fig = px.bar(scan_data, x='timestamp', y='scan_type', color='status', title='Recent Scans')
st.plotly_chart(fig)

# Recent Scans Table
st.subheader("Recent Scans")
st.dataframe(scan_data)

# Download Feature
def download_scans():
    filename = "scan_history.csv"
    scan_data.to_csv(filename, index=False)
    return filename

download_file = download_scans()
st.download_button(label="Download Scan History", data=open(download_file, "rb"), file_name=download_file, mime="text/csv")
