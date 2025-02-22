import streamlit as st

# Page config
st.set_page_config(
    page_title="Privacy & Terms",
    layout="wide",
    initial_sidebar_state="collapsed"
)

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def privacy_and_terms():
    init_style()
    
    # Create tabs for Privacy and Terms
    tab1, tab2 = st.tabs(["Privacy Policy", "Terms of Service"])
    
    with tab1:
        st.markdown("""
        <div class="policy-content">
            <h2>1. Information We Collect</h2>
            <p>We collect information that you provide directly to us, including:</p>
            <ul>
                <li>Account information (username, email)</li>
                <li>Network scan data and results</li>
                <li>System usage information</li>
            </ul>

            <h2>2. How We Use Your Information</h2>
            <p>We use the information we collect to:</p>
            <ul>
                <li>Provide and maintain our services</li>
                <li>Monitor and analyze usage patterns</li>
                <li>Protect against unauthorized access</li>
            </ul>

            <h2>3. Data Security</h2>
            <p>We implement appropriate security measures to protect your information.</p>

            <h2>4. Contact Us</h2>
            <p>If you have questions about this Privacy Policy, please contact us.</p>
        </div>
        """, unsafe_allow_html=True)
    
    with tab2:
        st.markdown("""
        <div class="policy-content">
            <h2>1. Acceptance of Terms</h2>
            <p>By accessing our service, you agree to these terms and conditions.</p>

            <h2>2. Use License</h2>
            <p>This tool should only be used on networks you own or have explicit permission to scan.</p>

            <h2>3. Disclaimer</h2>
            <ul>
                <li>The service is provided "as is" without warranties</li>
                <li>We are not responsible for any damages from use of the service</li>
                <li>Network scanning should comply with all applicable laws</li>
            </ul>

            <h2>4. Limitations</h2>
            <p>You agree not to:</p>
            <ul>
                <li>Use the service for illegal purposes</li>
                <li>Scan networks without authorization</li>
                <li>Attempt to breach or bypass security measures</li>
            </ul>

            <h2>5. Governing Law</h2>
            <p>These terms shall be governed by and construed in accordance with applicable laws.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Login"):
        st.switch_page("login.py")

if __name__ == "__main__":
    privacy_and_terms() 