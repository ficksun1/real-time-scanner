import streamlit as st
import nmap
import socket
import pandas as pd
from datetime import datetime
import threading
import queue
import ipaddress
from auth import DatabaseManager  # Add this import

# Page configuration
st.set_page_config(
    page_title="Network Scanner Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = []
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'is_scanning' not in st.session_state:
    st.session_state.is_scanning = False

def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def validate_ip_range(ip_range):
    """Validate IP address or range"""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def perform_scan(target, scan_type, result_queue):
    """Perform the network scan"""
    try:
        nm = nmap.PortScanner()
        
        # Define scan arguments based on scan type
        if scan_type == "Quick Scan":
            args = "-sn"  # Ping scan
        elif scan_type == "Basic Port Scan":
            args = "-sS -F"  # SYN scan on common ports
        else:  # Detailed Scan
            args = "-sS -sV -F"  # Remove -O flag as it requires root/sudo
        
        # Perform the scan
        nm.scan(hosts=target, arguments=args)
        
        results = []
        for host in nm.all_hosts():
            host_info = {
                'IP Address': host,
                'Status': nm[host].state(),
                'Hostname': nm[host].hostname(),
                'Ports': [],
                'Services': [],
                'OS': 'Not Available'  # Default value instead of accessing osmatch
            }
            
            if 'tcp' in nm[host]:
                for port, port_info in nm[host]['tcp'].items():
                    host_info['Ports'].append(port)
                    service_info = f"{port_info['name']} ({port_info.get('version', 'unknown')})"
                    host_info['Services'].append(service_info)
            
            results.append(host_info)
        
        result_queue.put(results)
    except Exception as e:
        result_queue.put(f"Error during scan: {str(e)}")

def save_scan_results(results, target, scan_type):
    """Save scan results to database"""
    if 'user_id' not in st.session_state:
        return
    
    db = DatabaseManager()
    for host_info in results:
        db.save_scan_result(
            st.session_state.user_id,
            target,
            scan_type,
            host_info
        )

def main():
    st.title("Network Security Scanner")
    
    # Sidebar for scan controls
    with st.sidebar:
        st.header("Scan Settings")
        
        # Get local IP for default value
        local_ip = get_local_ip()
        target = st.text_input("Target IP/Range", value=f"{local_ip}/24")
        
        scan_type = st.selectbox(
            "Scan Type",
            ["Quick Scan", "Basic Port Scan", "Detailed Scan"]
        )
        
        st.info("""
        Scan Types:
        - Quick Scan: Basic host discovery
        - Basic Port Scan: Common ports check
        - Detailed Scan: Full service detection
        """)
        
        start_scan = st.button("Start Scan", type="primary")
    
    # Main content area with tabs
    tab1, tab2 = st.tabs(["Current Scan", "Scan History"])
    
    with tab1:
        if start_scan:
            if not validate_ip_range(target):
                st.error("Invalid IP address or range")
            else:
                st.session_state.is_scanning = True
                result_queue = queue.Queue()
                
                # Start scan in separate thread
                scan_thread = threading.Thread(
                    target=perform_scan,
                    args=(target, scan_type, result_queue)
                )
                scan_thread.start()
                
                # Progress indicator
                with st.spinner("Scanning in progress..."):
                    scan_thread.join()
                    
                    try:
                        results = result_queue.get(timeout=1)
                        if isinstance(results, str) and "Error" in results:
                            st.error(results)
                        else:
                            # Store results in session state
                            scan_record = {
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'target': target,
                                'type': scan_type,
                                'results': results
                            }
                            st.session_state.scan_results = results
                            st.session_state.scan_history.append(scan_record)
                            
                            # Save results to database
                            save_scan_results(results, target, scan_type)
                            
                            st.success("Scan completed successfully!")
                            
                            # Display results
                            if results:
                                for host in results:
                                    with st.expander(f"Host: {host['IP Address']} ({host['Status']})"):
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.write("**Hostname:**", host['Hostname'])
                                            st.write("**Operating System:**", host['OS'])
                                        with col2:
                                            st.write("**Open Ports:**", ', '.join(map(str, host['Ports'])) if host['Ports'] else "None")
                                        
                                        if host['Services']:
                                            st.write("**Services:**")
                                            for service in host['Services']:
                                                st.write(f"- {service}")
                            else:
                                st.warning("No hosts found in the specified range")
                    except queue.Empty:
                        st.error("Scan timed out")
                
                st.session_state.is_scanning = False
        
        elif st.session_state.scan_results:
            # Display last scan results
            for host in st.session_state.scan_results:
                with st.expander(f"Host: {host['IP Address']} ({host['Status']})"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Hostname:**", host['Hostname'])
                        st.write("**Operating System:**", host['OS'])
                    with col2:
                        st.write("**Open Ports:**", ', '.join(map(str, host['Ports'])) if host['Ports'] else "None")
                    
                    if host['Services']:
                        st.write("**Services:**")
                        for service in host['Services']:
                            st.write(f"- {service}")
    
    with tab2:
        if st.session_state.scan_history:
            for scan in reversed(st.session_state.scan_history):
                with st.expander(f"Scan at {scan['timestamp']} - {scan['target']} ({scan['type']})"):
                    for host in scan['results']:
                        st.markdown(f"### {host['IP Address']} ({host['Status']})")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Hostname:**", host['Hostname'])
                            st.write("**Operating System:**", host['OS'])
                        with col2:
                            st.write("**Open Ports:**", ', '.join(map(str, host['Ports'])) if host['Ports'] else "None")
                        
                        if host['Services']:
                            st.write("**Services:**")
                            for service in host['Services']:
                                st.write(f"- {service}")
        else:
            st.info("No scan history available")

    # Footer
    st.markdown("---")
    st.caption("Network Scanner Dashboard - Use responsibly and only on authorized networks")

if __name__ == "__main__":
    main()
