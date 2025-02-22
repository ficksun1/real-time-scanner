import os
import pandas as pd
from datetime import datetime
from docx import Document
from docx.shared import Inches

class FileManager:
    def __init__(self, username):
        self.username = username
        self.base_path = "C:/NetworkScanner/Users"
        self.user_path = os.path.join(self.base_path, username)
        self.scans_path = os.path.join(self.user_path, "scans")
        self.reports_path = os.path.join(self.user_path, "reports")
        self.setup_directories()

    def setup_directories(self):
        """Create necessary directories if they don't exist"""
        for path in [self.user_path, self.scans_path, self.reports_path]:
            if not os.path.exists(path):
                os.makedirs(path)

    def save_scan_excel(self, scan_data, scan_id):
        """Save scan data to Excel file"""
        filename = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        filepath = os.path.join(self.scans_path, filename)
        
        df = pd.DataFrame([scan_data])
        df.to_excel(filepath, index=False)
        return filepath

    def save_scan_word(self, scan_data, scan_id):
        """Save scan data to Word file"""
        filename = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        filepath = os.path.join(self.reports_path, filename)
        
        doc = Document()
        doc.add_heading(f'Scan Report - {scan_id}', 0)
        
        # Add scan information
        doc.add_heading('Scan Details', level=1)
        doc.add_paragraph(f"Scan Time: {scan_data['scan_timestamp']}")
        doc.add_paragraph(f"IP Address: {scan_data['ip_address']}")
        doc.add_paragraph(f"Scan Type: {scan_data['scan_type']}")
        doc.add_paragraph(f"Status: {scan_data['status']}")
        
        # Add ports information if available
        if scan_data.get('ports'):
            doc.add_heading('Ports', level=1)
            doc.add_paragraph(f"Open Ports: {scan_data['ports']}")
        
        # Add services information if available
        if scan_data.get('services'):
            doc.add_heading('Services', level=1)
            doc.add_paragraph(f"Detected Services: {scan_data['services']}")
        
        doc.save(filepath)
        return filepath

    def generate_user_report(self, scan_history):
        """Generate comprehensive user report"""
        filename = f"user_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        filepath = os.path.join(self.reports_path, filename)
        
        doc = Document()
        doc.add_heading(f'User Report - {self.username}', 0)
        
        # Summary section
        doc.add_heading('Scan Summary', level=1)
        doc.add_paragraph(f"Total Scans: {len(scan_history)}")
        
        # Recent scans
        doc.add_heading('Recent Scans', level=1)
        for scan in scan_history[-5:]:  # Last 5 scans
            doc.add_heading(f"Scan {scan['id']}", level=2)
            doc.add_paragraph(f"Time: {scan['scan_timestamp']}")
            doc.add_paragraph(f"IP: {scan['ip_address']}")
            doc.add_paragraph(f"Type: {scan['scan_type']}")
            doc.add_paragraph(f"Status: {scan['status']}")
            
        doc.save(filepath)
        return filepath 