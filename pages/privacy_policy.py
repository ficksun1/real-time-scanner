import streamlit as st

# Page config
st.set_page_config(
    page_title="Privacy Policy",
    layout="wide",
    initial_sidebar_state="collapsed"
)

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def privacy_policy():
    init_style()
    
    st.title("Privacy Policy")
    
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
    
    # Back button
    if st.button("← Back to Login"):
        st.switch_page("login.py")

if __name__ == "__main__":
    privacy_policy() 