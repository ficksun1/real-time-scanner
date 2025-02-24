import streamlit as st

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def display_security_tips():
    init_style()
    
    st.title("Network Security Tips")
    
    # Common Vulnerabilities
    with st.expander("Common Network Vulnerabilities", expanded=True):
        st.markdown("""
        <div class='security-card'>
            <h3>Top Network Vulnerabilities</h3>
            <ul>
                <li>🔓 <strong>Open Ports:</strong> Unnecessary exposed services</li>
                <li>🔑 <strong>Weak Passwords:</strong> Default or easily guessable credentials</li>
                <li>🔄 <strong>Outdated Software:</strong> Unpatched security vulnerabilities</li>
                <li>🛡️ <strong>Misconfigured Firewalls:</strong> Improper access controls</li>
                <li>📡 <strong>Unsecured Wi-Fi:</strong> Weak encryption or open networks</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Prevention Strategies
    with st.expander("Prevention Strategies"):
        st.markdown("""
        <div class='security-card'>
            <h3>Security Best Practices</h3>
            <ol>
                <li>Regular Security Audits</li>
                <li>Strong Password Policies</li>
                <li>Network Segmentation</li>
                <li>Updated Firmware/Software</li>
                <li>Employee Security Training</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    display_security_tips() 