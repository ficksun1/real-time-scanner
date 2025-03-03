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
from pages.nmap_commands import display_nmap_commands  # Import the function

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
    
    with col1:
        target = st.text_input(
            "Target IP/Range",
            placeholder="e.g., 192.168.1.1 or 192.168.1.0/24",
            help="Enter a single IP or IP range in CIDR notation"
        )
        
    with col2:
        scan_type = st.selectbox(
            "Scan Type",
            ["Quick Scan", "Full Port Scan", "OS Detection", "Service Detection"],
            help="Select the type of scan to perform"
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
        if scan_type == "Quick Scan":
            args = "-sn -T4"  # Fast ping scan
        elif scan_type == "Full Port Scan":
            args = "-sS -T4 -p- -Pn"  # SYN scan on all ports, treat hosts as online
        elif scan_type == "OS Detection":
            args = "-sS -O -T4 -Pn"  # OS detection with SYN scan
        else:  # Service Detection
            args = "-sV -T4 -Pn -sS"  # Version detection with SYN scan
        
        # Add common options for better accuracy
        args += " --min-rate=1000 --max-retries=2"
        
        # Perform the scan
        st.info(f"Starting {scan_type} on {target}...")
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
            
            # Get OS information if available
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
                        
                        # Enhanced service information
                        service_info = []
                        if port_info['name'] != 'unknown':
                            service_info.append(port_info['name'])
                        if 'product' in port_info and port_info['product']:
                            service_info.append(port_info['product'])
                        if 'version' in port_info and port_info['version']:
                            service_info.append(f"v{port_info['version']}")
                        
                        service_str = f"Port {port}: {' - '.join(service_info)}"
                        host_info['Services'].append(service_str)
            
            # Add vulnerability checks for common ports
            if host_info['Ports']:
                host_info['Vulnerabilities'] = check_common_vulnerabilities(host_info['Ports'])
            
            results.append(host_info)
        
        result_queue.put(results)
        
    except Exception as e:
        result_queue.put(f"Error during scan: {str(e)}")

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
        else:
            st.warning("No hosts found in the specified range")
            
    except Exception as e:
        st.error(f"Error during scan: {str(e)}")

def display_results(results):
    """Display enhanced scan results"""
    for host in results:
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

def create_dropdown_menu():
    """Create a dropdown menu for navigation"""
    menu_options = [
        "Scanner",
        "Documentation",
        "Security Tips",
        "Network Tools",
        "Vulnerabilities",
        "Profile",
        "Report Templates",
        "Nmap Commands"  # Add the new page here
    ]
    
    selected_page = st.selectbox("Select a Page", menu_options)
    
    return selected_page

def main():
    init_style()
    create_menu()
    
    # Initialize session state variables if they don't exist
    if 'is_scanning' not in st.session_state:
        st.session_state.is_scanning = False
    
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = []
    
    selected_page = create_dropdown_menu()
    
    if selected_page == "Scanner":
        # Existing scanner code...
        with st.container():
            tab1, tab2 = st.tabs(["🎯 Scanner", "📊 Results"])
            
            with tab1:
                if not st.session_state.is_scanning:
                    target, scan_type, start_scan = get_scan_inputs()
                    
                    if start_scan:
                        st.session_state.is_scanning = True
                        result_queue = queue.Queue()
                        
                        with st.spinner("🔍 Scanning in progress..."):
                            scan_thread = threading.Thread(
                                target=perform_scan,
                                args=(target, scan_type, result_queue)
                            )
                            scan_thread.start()
                            
                            try:
                                results = result_queue.get(timeout=300)
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
    elif selected_page == "Nmap Commands":
        display_nmap_commands()  # Call the new function to display Nmap commands
    # Handle other pages similarly...

if __name__ == "__main__":
    main()
