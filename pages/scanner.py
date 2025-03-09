import streamlit as st
import nmap
import socket
import pandas as pd
from datetime import datetime
import threading
import queue
import ipaddress
from auth import DatabaseManager  # Add this import
from file_manager import FileManager
import time

# Page configuration
st.set_page_config(
    page_title="Network Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    # Add header directly instead of reading from file
    st.markdown("""
        <div class="main-header">
            <h1 class="cyber-title">Network Security Scanner</h1>
            <div class="cyber-line"></div>
        </div>
    """, unsafe_allow_html=True)

def create_menu():
    with st.sidebar:
        st.markdown("""
        <div class='sidebar-header'>
            <h3>🔐 Network Scanner</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # Navigation Menu
        st.markdown("### 📌 Navigation")
        
        menu_items = {
            "🔍 Scanner": "scanner",
            "📚 Documentation": "documentation",
            "🛡️ Security Tips": "security_tips",
            "🔧 Network Tools": "network_tools",
            "📋 Vulnerabilities": "vulnerabilities",
            "👤 Profile": "profile"
        }
        
        for label, page in menu_items.items():
            if st.button(label, use_container_width=True, key=f"menu_{page}"):
                st.switch_page(f"pages/{page}.py")
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True, key="logout"):
            handle_logout()
            
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

def get_scan_inputs():
    st.markdown("""
    <div class='scan-config-card'>
        <h3>Scan Configuration</h3>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col2:
        scan_type = st.selectbox(
            "Scan Type",
            ["Automatic Network Scan", "Full Port Scan", "OS Detection", "Service Detection"],
            help="Select the type of scan to perform"
        )
    
    with col1:
        if scan_type == "Automatic Network Scan":
            st.info("Automatic scan will detect and scan all hosts in your network")
            target = f"{get_local_ip().rsplit('.', 1)[0]}.0/24"  # Automatically set to local subnet
            st.text(f"Target network: {target}")
        else:
            target = st.text_input(
                "Target IP/Range",
                placeholder="e.g., 192.168.1.1 or 192.168.1.0/24",
                help="Enter a single IP or IP range in CIDR notation"
            )
    
    # Start scan button with custom styling
    col1, col2, col3 = st.columns([2,1,2])
    with col2:
        start_scan = st.button(
            "🚀 Start Scan",
            type="primary",
            use_container_width=True
        )
        
        if start_scan and not validate_ip_range(target):
            st.error("Invalid IP address or range")
            return target, scan_type, False
    
    return target, scan_type, start_scan

def validate_ip_range(ip_range):
    """Validate IP address or range"""
    try:
        # Check if it's a CIDR range
        if '/' in ip_range:
            ipaddress.ip_network(ip_range)
        else:
            ipaddress.ip_address(ip_range)
        return True
    except ValueError:
        return False

def perform_scan(target, scan_type, result_queue):
    """Perform the network scan with enhanced accuracy"""
    try:
        nm = nmap.PortScanner()
        
        # Define scan arguments based on scan type
        if scan_type == "Automatic Network Scan":
            # First do a fast ping sweep to find active hosts
            args = "-sn -T4"  # Fast ping scan
            nm.scan(hosts=target, arguments=args)
            
            # Get all active hosts
            active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
            
            results = []
            # Now scan each active host for more details
            for host in active_hosts:
                # Perform a focused scan on the active host
                service_args = "-sV -sS -F -O --version-intensity 5"  # Balanced scan for services and OS
                try:
                    nm.scan(hosts=host, arguments=service_args)
                    
                    host_info = {
                        'IP Address': host,
                        'Status': 'up',
                        'Hostname': nm[host].hostname() if nm[host].hostname() else 'N/A',
                        'Ports': [],
                        'Services': [],
                        'OS': 'Unknown'
                    }
                    
                    # Get OS information
                    if 'osmatch' in nm[host] and nm[host]['osmatch']:
                        os_matches = nm[host]['osmatch']
                        if os_matches and len(os_matches) > 0:
                            best_match = os_matches[0]
                            host_info['OS'] = f"{best_match['name']} ({best_match['accuracy']}% accuracy)"
                    
                    # Get port and service information
                    if 'tcp' in nm[host]:
                        for port, port_info in nm[host]['tcp'].items():
                            if port_info['state'] == 'open':
                                host_info['Ports'].append(port)
                                
                                service_info = []
                                if port_info['name'] != 'unknown':
                                    service_info.append(port_info['name'])
                                if 'product' in port_info and port_info['product']:
                                    service_info.append(port_info['product'])
                                if 'version' in port_info and port_info['version']:
                                    service_info.append(f"v{port_info['version']}")
                                
                                service_str = f"Port {port}: {' - '.join(service_info)}"
                                host_info['Services'].append(service_str)
                    
                    # Add vulnerability checks
                    if host_info['Ports']:
                        host_info['Vulnerabilities'] = check_common_vulnerabilities(host_info['Ports'])
                    
                    results.append(host_info)
                    
                except Exception as e:
                    st.warning(f"Could not get detailed information for host {host}: {str(e)}")
                    # Add basic host information even if detailed scan fails
                    results.append({
                        'IP Address': host,
                        'Status': 'up',
                        'Hostname': 'N/A',
                        'Ports': [],
                        'Services': [],
                        'OS': 'Unknown'
                    })
            
            result_queue.put(results)
            
        else:
            # Original scan logic for other scan types
            args = {
                "Full Port Scan": "-sS -T4 -p- -Pn",
                "OS Detection": "-sS -O -T4 -Pn",
                "Service Detection": "-sV -T4 -Pn -sS"
            }[scan_type]
            
            args += " --min-rate=1000 --max-retries=2"
            nm.scan(hosts=target, arguments=args)
            
            results = []
            for host in nm.all_hosts():
                host_info = {
                    'IP Address': host,
                    'Status': nm[host].state(),
                    'Hostname': nm[host].hostname() if nm[host].hostname() else 'N/A',
                    'Ports': [],
                    'Services': [],
                    'OS': 'Unknown'
                }
                
                # Rest of the original scanning logic...
                if 'osmatch' in nm[host] and nm[host]['osmatch']:
                    os_matches = nm[host]['osmatch']
                    if os_matches and len(os_matches) > 0:
                        best_match = os_matches[0]
                        host_info['OS'] = f"{best_match['name']} ({best_match['accuracy']}% accuracy)"
                
                if 'tcp' in nm[host]:
                    for port, port_info in nm[host]['tcp'].items():
                        if port_info['state'] == 'open':
                            host_info['Ports'].append(port)
                            service_info = []
                            if port_info['name'] != 'unknown':
                                service_info.append(port_info['name'])
                            if 'product' in port_info and port_info['product']:
                                service_info.append(port_info['product'])
                            if 'version' in port_info and port_info['version']:
                                service_info.append(f"v{port_info['version']}")
                            
                            service_str = f"Port {port}: {' - '.join(service_info)}"
                            host_info['Services'].append(service_str)
                
                if host_info['Ports']:
                    host_info['Vulnerabilities'] = check_common_vulnerabilities(host_info['Ports'])
                
                results.append(host_info)
            
            result_queue.put(results)
            
    except Exception as e:
        error_msg = f"Error during scan: {str(e)}"
        result_queue.put(error_msg)

def check_common_vulnerabilities(ports):
    """Check for common vulnerabilities based on open ports"""
    vulnerabilities = []
    
    common_vulnerable_ports = {
        21: "FTP - Potential anonymous access or weak authentication",
        23: "Telnet - Unencrypted communication protocol",
        53: "DNS - Potential zone transfer or cache poisoning",
        80: "HTTP - Web server might be vulnerable to various web attacks",
        443: "HTTPS - Check SSL/TLS version and configuration",
        3389: "RDP - Remote Desktop Protocol exposure",
        3306: "MySQL - Database port exposure",
        445: "SMB - File sharing protocol, check for EternalBlue",
        139: "NetBIOS - Legacy Windows networking",
        22: "SSH - Check for outdated versions"
    }
    
    for port in ports:
        if port in common_vulnerable_ports:
            vulnerabilities.append(common_vulnerable_ports[port])
    
    return vulnerabilities

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

def handle_logout():
    """Handle user logout"""
    # Clear session state
    for key in ['logged_in', 'username', 'user_id', 'token']:
        if key in st.session_state:
            del st.session_state[key]
    
    # Redirect to login page
    st.switch_page("login.py")

def handle_scan(target, scan_type, results):
    """Handle scan execution and saving results"""
    try:
        file_manager = FileManager(st.session_state.username)
        
        # Process scan results
        if results and len(results) > 0:
            st.success("Scan completed successfully!")
            
            # For Automatic Network Scan, show a summary first
            if scan_type == "Automatic Network Scan":
                online_hosts = [host for host in results if host['Status'] == 'up']
                st.info(f"Found {len(online_hosts)} active hosts in your network")
                
                # Create a summary table
                summary_data = []
                for host in online_hosts:
                    summary_data.append({
                        "IP Address": host['IP Address'],
                        "Hostname": host['Hostname'],
                        "OS": host['OS'],
                        "Open Ports": len(host['Ports'])
                    })
                
                if summary_data:
                    st.dataframe(summary_data)
            
            for host in results:
                scan_data = {
                    'scan_timestamp': datetime.now(),
                    'ip_address': host['IP Address'],
                    'scan_type': scan_type,
                    'status': host['Status'],
                    'ports': ', '.join(map(str, host['Ports'])) if host['Ports'] else None,
                    'services': ', '.join(host['Services']) if host['Services'] else None,
                    'os_info': host['OS']
                }
                
                # Generate unique scan ID
                scan_id = f"{st.session_state.username}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                # Save to files silently
                file_manager.save_scan_excel(scan_data, scan_id)
                file_manager.save_scan_word(scan_data, scan_id)
                
                # Display results
                with st.expander(f"🖥️ Host: {host['IP Address']} ({host['Status']})"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**🌐 Hostname:** {host['Hostname']}")
                        st.markdown(f"**💻 Operating System:** {host['OS']}")
                    with col2:
                        ports = ', '.join(map(str, host['Ports'])) if host['Ports'] else "None"
                        st.markdown(f"**🔌 Open Ports:** {ports}")
                    
                    if host['Services']:
                        st.markdown("**🔧 Services:**")
                        for service in host['Services']:
                            st.markdown(f"- {service}")
                    
                    if 'Vulnerabilities' in host and host['Vulnerabilities']:
                        st.markdown("**⚠️ Potential Vulnerabilities:**")
                        for vuln in host['Vulnerabilities']:
                            st.markdown(f"- {vuln}")
        else:
            st.warning("No hosts found in the specified range")
            
    except Exception as e:
        st.error(f"Error during scan: {str(e)}")

def update_progress(progress_bar, progress_text, stages):
    """Update progress bar using a thread-safe approach"""
    # We'll use session state to communicate between threads
    if 'progress_stage' not in st.session_state:
        st.session_state.progress_stage = 0
        st.session_state.progress_text = "Initializing network scan..."
    
    # This function will be called from the main thread
    current_stage = st.session_state.progress_stage
    if current_stage < len(stages):
        progress = (current_stage + 1) / len(stages)
        progress_bar.progress(progress)
        progress_text.text(stages[current_stage])
        st.session_state.progress_stage += 1
        # Schedule the next update
        if current_stage < len(stages) - 1:
            time.sleep(3)  # Wait between stages
            st.rerun()  # Trigger a rerun to update the progress

def display_results(results):
    """Display enhanced scan results"""
    # Check if results is an error message (string)
    if isinstance(results, str):
        st.error(f"Scan error: {results}")
        return
        
    for host in results:
        # Ensure host is a dictionary before accessing its keys
        if not isinstance(host, dict):
            st.error(f"Invalid host data: {host}")
            continue
            
        with st.expander(f"🖥️ Host: {host['IP Address']} ({host['Status']})"):
            # Basic Information
            st.markdown("### 📌 Basic Information")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**🌐 Hostname:** {host['Hostname']}")
                st.markdown(f"**💻 Operating System:** {host['OS']}")
            with col2:
                ports = ', '.join(map(str, host['Ports'])) if host['Ports'] else "None"
                st.markdown(f"**🔌 Open Ports:** {ports}")
            
            # Services
            if host['Services']:
                st.markdown("### 🔧 Services Detected")
                for service in host['Services']:
                    st.markdown(f"- {service}")
            
            # Vulnerabilities
            if 'Vulnerabilities' in host and host['Vulnerabilities']:
                st.markdown("### ⚠️ Potential Vulnerabilities")
                for vuln in host['Vulnerabilities']:
                    st.markdown(f"- {vuln}")
                
                st.info("Note: These are potential vulnerabilities based on open ports. Further testing is recommended.")

def main():
    init_style()
    create_menu()
    
    if 'is_scanning' not in st.session_state:
        st.session_state.is_scanning = False
    
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = []
    
    # Main content area
    with st.container():
        tab1, tab2 = st.tabs(["🎯 Scanner", "📊 Results"])
        
        with tab1:
            if not st.session_state.is_scanning:
                target, scan_type, start_scan = get_scan_inputs()
                
                if start_scan:
                    st.session_state.is_scanning = True
                    result_queue = queue.Queue()
                    
                    with st.spinner("🔍 Scanning in progress..."):
                        if scan_type == "Automatic Network Scan":
                            st.info("Discovering hosts in your network. This may take a few minutes...")
                            progress_bar = st.progress(0)
                            
                            # Simple progress indication
                            for i in range(100):
                                time.sleep(0.1)
                                progress_bar.progress(i + 1)
                        
                        scan_thread = threading.Thread(
                            target=perform_scan,
                            args=(target, scan_type, result_queue)
                        )
                        scan_thread.daemon = True
                        scan_thread.start()
                        
                        try:
                            results = result_queue.get(timeout=300)
                            if scan_type == "Automatic Network Scan":
                                progress_bar.empty()
                            
                            if isinstance(results, str) and "Error" in results:
                                st.error(results)
                                st.session_state.scan_results = []
                            else:
                                st.session_state.scan_results = results
                                handle_scan(target, scan_type, results)
                        except queue.Empty:
                            st.error("⚠️ Scan timed out")
                    
                    st.session_state.is_scanning = False
        
        with tab2:
            if st.session_state.scan_results:
                display_results(st.session_state.scan_results)
            else:
                st.info("No scan results available yet. Run a scan to see results here.")

if __name__ == "__main__":
    main()
