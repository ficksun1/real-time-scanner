import streamlit as st
from docx import Document
import datetime

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def create_executive_report(scan_results):
    doc = Document()
    doc.add_heading('Network Security Audit Report', 0)
    doc.add_paragraph(f'Generated on: {datetime.datetime.now()}')
    # Add more report sections 
    return doc

def display_report_templates():
    init_style()
    st.title("Report Templates")
    
    template_type = st.selectbox(
        "Select Report Template",
        ["Executive Summary", "Technical Report", "Compliance Report"]
    )
    
    if template_type == "Executive Summary":
        st.markdown("""
        <div class='report-preview'>
            <h3>Executive Summary Template</h3>
            <p>Includes:</p>
            <ul>
                <li>Overview of scan results</li>
                <li>Key findings and risks</li>
                <li>Recommendations</li>
                <li>Summary metrics</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
    if st.button("Generate Template"):
        st.success("Template generated! Check your reports folder.")

if __name__ == "__main__":
    display_report_templates() 