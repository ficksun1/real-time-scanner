import streamlit as st
import scapy.all as scapy
from scapy.layers import http
import pandas as pd
from datetime import datetime
import threading
import queue
import time
from collections import Counter
import ipaddress

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

class NetworkIDS:
    def __init__(self):
        # Define threshold values for different attacks
        self.syn_flood_threshold = 100  # SYN packets per second
        self.port_scan_threshold = 20   # Different ports per second
        self.ping_flood_threshold = 50   # ICMP packets per second
        
        # Track packet statistics
        self.packet_stats = {
            'syn_count': Counter(),
            'port_scan': Counter(),
            'icmp_count': Counter(),
            'suspicious_ports': set([22, 23, 3389, 445, 135, 139])  # Known vulnerable ports
        }
        
    def analyze_packet(self, packet):
        timestamp = datetime.now()
        alerts = []
        
        if packet.haslayer(scapy.TCP):
            # Check for SYN flood
            if packet[scapy.TCP].flags == 2:  # SYN flag
                self.packet_stats['syn_count'][packet[scapy.IP].src] += 1
                if self.packet_stats['syn_count'][packet[scapy.IP].src] > self.syn_flood_threshold:
                    alerts.append({
                        'type': 'SYN Flood Attack',
                        'source': packet[scapy.IP].src,
                        'severity': 'High',
                        'description': 'Possible SYN flood attack detected. Large number of SYN packets from single source.'
                    })
            
            # Check for port scanning
            self.packet_stats['port_scan'][(packet[scapy.IP].src, packet[scapy.TCP].dport)] += 1
            unique_ports = len(set(port for _, port in self.packet_stats['port_scan'].keys()))
            if unique_ports > self.port_scan_threshold:
                alerts.append({
                    'type': 'Port Scan',
                    'source': packet[scapy.IP].src,
                    'severity': 'Medium',
                    'description': 'Possible port scanning activity detected. Multiple ports being probed.'
                })
            
            # Check for suspicious port access
            if packet[scapy.TCP].dport in self.packet_stats['suspicious_ports']:
                alerts.append({
                    'type': 'Suspicious Port Access',
                    'source': packet[scapy.IP].src,
                    'severity': 'Medium',
                    'description': f'Access attempt to suspicious port {packet[scapy.TCP].dport}'
                })
        
        elif packet.haslayer(scapy.ICMP):
            # Check for ICMP flood
            self.packet_stats['icmp_count'][packet[scapy.IP].src] += 1
            if self.packet_stats['icmp_count'][packet[scapy.IP].src] > self.ping_flood_threshold:
                alerts.append({
                    'type': 'ICMP Flood',
                    'source': packet[scapy.IP].src,
                    'severity': 'Medium',
                    'description': 'Possible ICMP flood attack detected.'
                })
        
        return alerts

def capture_packets(packet_queue, stop_event, num_packets=300):
    ids = NetworkIDS()
    packets_captured = 0
    
    def packet_callback(packet):
        nonlocal packets_captured
        if packets_captured < num_packets and not stop_event.is_set():
            packet_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'N/A',
                'dest_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'N/A',
                'protocol': packet.name,
                'length': len(packet),
                'alerts': ids.analyze_packet(packet)
            }
            packet_queue.put(packet_info)
            packets_captured += 1

    try:
        scapy.sniff(prn=packet_callback, store=False, count=num_packets)
    except Exception as e:
        packet_queue.put(f"Error during packet capture: {str(e)}")

def main():
    init_style()
    st.title("Network Monitor & IDS")
    
    if 'monitoring' not in st.session_state:
        st.session_state.monitoring = False
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔍 Real-time Network Monitoring
        This tool captures network packets and analyzes them for potential security threats.
        """)
    
    with col2:
        if not st.session_state.monitoring:
            if st.button("🚀 Start Monitoring", type="primary", use_container_width=True):
                st.session_state.monitoring = True
                st.rerun()
        else:
            if st.button("⏹️ Stop Monitoring", type="secondary", use_container_width=True):
                st.session_state.monitoring = False
                st.rerun()
    
    if st.session_state.monitoring:
        packet_queue = queue.Queue()
        stop_event = threading.Event()
        
        # Create placeholder for live updates
        status_placeholder = st.empty()
        table_placeholder = st.empty()
        alert_placeholder = st.empty()
        
        # Start packet capture thread
        capture_thread = threading.Thread(
            target=capture_packets,
            args=(packet_queue, stop_event)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        # Initialize data storage
        packets_data = []
        alerts = []
        
        try:
            with st.spinner("📡 Capturing network packets..."):
                while len(packets_data) < 300 and not stop_event.is_set():
                    try:
                        packet_info = packet_queue.get(timeout=1)
                        if isinstance(packet_info, str) and "Error" in packet_info:
                            st.error(packet_info)
                            break
                        
                        packets_data.append(packet_info)
                        if packet_info['alerts']:
                            alerts.extend(packet_info['alerts'])
                        
                        # Update status
                        status_placeholder.info(f"Captured {len(packets_data)} packets")
                        
                        # Show live packet data
                        df = pd.DataFrame([{
                            'Time': p['timestamp'],
                            'Source IP': p['source_ip'],
                            'Destination IP': p['dest_ip'],
                            'Protocol': p['protocol'],
                            'Length': p['length']
                        } for p in packets_data])
                        table_placeholder.dataframe(df, use_container_width=True)
                        
                        # Show alerts if any
                        if alerts:
                            alert_placeholder.error("🚨 Security Alerts Detected!")
                            for alert in alerts:
                                alert_placeholder.markdown(f"""
                                    **Alert Type:** {alert['type']}  
                                    **Source:** {alert['source']}  
                                    **Severity:** {alert['severity']}  
                                    **Description:** {alert['description']}  
                                    ---
                                """)
                        else:
                            alert_placeholder.success("✅ No security threats detected")
                        
                    except queue.Empty:
                        continue
                    
        except Exception as e:
            st.error(f"Error during monitoring: {str(e)}")
        finally:
            stop_event.set()
            st.session_state.monitoring = False

if __name__ == "__main__":
    main() 