import streamlit as st

# Page config
st.set_page_config(
    page_title="Terms of Service",
    layout="wide",
    initial_sidebar_state="collapsed"
)

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def terms_of_service():
    init_style()
    
    st.title("Terms of Service")
    
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
    terms_of_service() 