import streamlit as st

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def display_documentation():
    init_style()
    
    st.title("Network Scanning Guide")
    
    # Introduction
    st.markdown("""
    <div class='doc-section'>
        <h1>Understanding Network Scanning</h1>
        <p>
        Network scanning is a crucial component of cybersecurity that helps identify potential vulnerabilities
        and ensure the security of your network infrastructure. This guide explains different types of scans
        and their importance in maintaining network security.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Scan Types Explanation
    st.subheader("Types of Scans")
    
    # Quick Scan
    with st.expander("Quick Scan", expanded=True):
        st.markdown("""
        <div class='scan-type-card'>
            <h3>Quick Scan</h3>
            <p><strong>What it does:</strong> Performs rapid host discovery and basic port checking.</p>
            <p><strong>Best used for:</strong></p>
            <ul>
                <li>Initial network reconnaissance</li>
                <li>Quick host availability checks</li>
                <li>Basic network mapping</li>
            </ul>
            <p><strong>Advantages:</strong></p>
            <ul>
                <li>Fast execution</li>
                <li>Minimal network impact</li>
                <li>Good for regular monitoring</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Full Port Scan
    with st.expander("Full Port Scan"):
        st.markdown("""
        <div class='scan-type-card'>
            <h3>Full Port Scan</h3>
            <p><strong>What it does:</strong> Comprehensive scan of all 65,535 ports on target hosts.</p>
            <p><strong>Best used for:</strong></p>
            <ul>
                <li>Detailed security audits</li>
                <li>Finding unauthorized services</li>
                <li>Complete network service inventory</li>
            </ul>
            <p><strong>Advantages:</strong></p>
            <ul>
                <li>Thorough coverage</li>
                <li>Identifies all open ports</li>
                <li>Reveals potential security gaps</li>
            </ul>
            <div class='warning-box'>
                <p>⚠️ Note: This scan type takes longer and generates more network traffic.</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # OS Detection
    with st.expander("OS Detection"):
        st.markdown("""
        <div class='scan-type-card'>
            <h3>OS Detection</h3>
            <p><strong>What it does:</strong> Identifies operating systems running on network devices.</p>
            <p><strong>Best used for:</strong></p>
            <ul>
                <li>System inventory management</li>
                <li>Identifying outdated systems</li>
                <li>Security compliance checks</li>
            </ul>
            <p><strong>Advantages:</strong></p>
            <ul>
                <li>Helps identify vulnerable systems</li>
                <li>Assists in patch management</li>
                <li>Supports network documentation</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Service Detection
    with st.expander("Service Detection"):
        st.markdown("""
        <div class='scan-type-card'>
            <h3>Service Detection</h3>
            <p><strong>What it does:</strong> Identifies and analyzes services running on open ports.</p>
            <p><strong>Best used for:</strong></p>
            <ul>
                <li>Service version auditing</li>
                <li>Vulnerability assessment</li>
                <li>Security baseline creation</li>
            </ul>
            <p><strong>Advantages:</strong></p>
            <ul>
                <li>Detailed service information</li>
                <li>Version-specific vulnerability checking</li>
                <li>Comprehensive security assessment</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Best Practices
    st.subheader("Best Practices")
    st.markdown("""
    <div class='best-practices-card'>
        <h1>Scanning Best Practices</h1>
        <ul>
            <li>Always obtain proper authorization before scanning networks</li>
            <li>Schedule intensive scans during off-peak hours</li>
            <li>Regularly backup scan results for compliance</li>
            <li>Monitor system resources during scans</li>
            <li>Follow up on identified vulnerabilities</li>
            <li>Document all scanning activities</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Add custom CSS
    st.markdown("""
    <style>
    .doc-section {
        background: rgba(1, 1, 43, 0.7);
        padding: 2rem;
        border-radius: 15px;
        border: 1px solid var(--primary-color);
        margin-bottom: 2rem;
    }
    
    .scan-type-card {
        background: rgba(1, 1, 43, 0.7);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid var(--secondary-color);
        margin: 1rem 0;
    }
    
    .warning-box {
        background: rgba(255, 42, 109, 0.1);
        padding: 1rem;
        border-radius: 5px;
        border-left: 3px solid var(--primary-color);
        margin-top: 1rem;
    }
    
    .best-practices-card {
        background: rgba(1, 1, 43, 0.7);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid var(--accent-2);
        margin: 1rem 0;
    }
    
    .scan-type-card h3 {
        color: var(--secondary-color);
        margin-bottom: 1rem;
    }
    
    .scan-type-card ul {
        margin-left: 1.5rem;
        margin-bottom: 1rem;
    }
    
    .scan-type-card li {
        margin-bottom: 0.5rem;
    }
    </style>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    display_documentation() 