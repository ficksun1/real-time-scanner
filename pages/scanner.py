import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import IP, TCP, UDP, sniff
from collections import defaultdict
import time
from datetime import datetime, timedelta
import threading
import logging
from typing import Dict, List, Optional, Tuple
import socket
import geoip2.database
from dataclasses import dataclass
from auth import AuthManager

# Set page config
st.set_page_config(page_title="Network Traffic Analysis", layout="wide")

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'kali',
    'database': 'network_scanner'
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='network_scanner.log'
)
logger = logging.getLogger(__name__)

@dataclass
class NetworkConfig:
    """Configuration settings for network scanning"""
    max_packets: int = 10000
    cleanup_interval: int = 60
    data_retention_period: int = 300
    rate_limit: int = 1000
    interface: str = None
    packet_filter: str = "ip"

class PacketProcessor:
    """Process and analyze network packets"""
    def __init__(self, user_id: int, config: NetworkConfig):
        self.user_id = user_id
        self.config = config
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.db_manager = AuthManager()
        self.last_cleanup = time.time()
        self.packet_rates = defaultdict(int)
        
        try:
            self.geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")
            self.geo_reader = None

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                current_time = datetime.now()
                
                if self.check_rate_limit():
                    return

                with self.lock:
                    packet_info = {
                        'timestamp': current_time,
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (current_time - self.start_time).total_seconds()
                    }

                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport
                        })
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1
                    self.periodic_cleanup()

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_protocol_name(self, protocol_num: int) -> str:
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            if not self.packet_data:
                return pd.DataFrame(columns=[
                    'timestamp', 'source', 'destination', 'protocol',
                    'size', 'src_port', 'dst_port', 'time_relative'
                ])
            return pd.DataFrame(self.packet_data)

def create_sidebar():
    with st.sidebar:
        logo_url = "https://cdn-icons-png.flaticon.com/512/2526/2526190.png"
        try:
            st.image(logo_url, width=100)
        except Exception:
            st.title("Scanner")
        
        st.divider()
        st.header("Network Scanner")
        st.subheader("User Profile")
        st.write(f"Welcome, {st.session_state.username}")
        
        page = st.radio(
            "Select Page",
            ["Live Traffic", "Port Scanner", "Network Education", "Settings"]
        )
        
        refresh_rate = st.slider("Refresh Rate (seconds)", 1, 10, 2)
        max_packets = st.slider("Max Packets", 100, 1000, 200)
        
        if st.button("Logout"):
            handle_logout()
            
        return page, refresh_rate, max_packets

def handle_logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()

def main():
    if 'logged_in' not in st.session_state or not st.session_state.logged_in:
        st.error("Please login first")
        st.stop()

    if 'processor' not in st.session_state:
        processor = PacketProcessor(st.session_state.user_id, NetworkConfig())
        st.session_state.processor = processor
        st.session_state.start_time = time.time()

    page, refresh_rate, max_packets = create_sidebar()
    
    if page == "Live Traffic":
        df = st.session_state.processor.get_dataframe()
        # Display live traffic visualization here
        time.sleep(refresh_rate)
        st.rerun()

if __name__ == "__main__":
    main()
