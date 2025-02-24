import streamlit as st
import socket
import whois
import requests
import platform
import subprocess

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def ping(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        output = subprocess.check_output(command).decode()
        return output
    except:
        return "Host unreachable"

def display_tools():
    init_style()
    st.title("Network Tools")
    
    tool = st.selectbox("Select Tool", [
        "DNS Lookup",
        "WHOIS Lookup",
        "Ping Test",
        "HTTP Header Check"
    ])
    
    if tool == "DNS Lookup":
        domain = st.text_input("Enter domain")
        if domain:
            try:
                ip = socket.gethostbyname(domain)
                st.success(f"IP Address: {ip}")
            except:
                st.error("Could not resolve domain")
                
    elif tool == "WHOIS Lookup":
        domain = st.text_input("Enter domain for WHOIS lookup")
        if domain:
            try:
                w = whois.whois(domain)
                st.json(w)
            except:
                st.error("Could not fetch WHOIS information")
                
    elif tool == "Ping Test":
        host = st.text_input("Enter host to ping")
        if host:
            result = ping(host)
            st.code(result)
            
    elif tool == "HTTP Header Check":
        url = st.text_input("Enter URL")
        if url:
            try:
                response = requests.head(url)
                st.json(dict(response.headers))
            except:
                st.error("Could not fetch headers")

if __name__ == "__main__":
    display_tools() 