import streamlit as st
import pandas as pd

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def get_sample_vulnerabilities():
    return pd.DataFrame({
        'CVE': ['CVE-2021-44228', 'CVE-2021-34527', 'CVE-2021-26855'],
        'Name': ['Log4Shell', 'PrintNightmare', 'Microsoft Exchange Server'],
        'Severity': ['High', 'High', 'Critical'],
        'Description': [
            'Remote code execution vulnerability in Log4j',
            'Windows Print Spooler remote code execution vulnerability',
            'Microsoft Exchange Server remote code execution vulnerability'
        ],
        'Published': ['2021-12-10', '2021-07-01', '2021-03-02']
    })

def display_vulnerabilities():
    init_style()
    st.title("Vulnerability Database")
    
    # Search functionality
    search = st.text_input("Search Vulnerabilities")
    
    # Filter options
    severity = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"])
    
    # Get and filter data
    df = get_sample_vulnerabilities()
    
    if search:
        df = df[df.apply(lambda x: x.str.contains(search, case=False)).any(axis=1)]
    if severity:
        df = df[df['Severity'].isin(severity)]
    
    # Display vulnerabilities table
    if not df.empty:
        st.dataframe(df)
    else:
        st.info("No vulnerabilities found matching your criteria")

if __name__ == "__main__":
    display_vulnerabilities() 