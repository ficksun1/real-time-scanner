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
        st.title("Privacy Policy", help=None)
        
        with st.container():
            st.subheader("1. Information We Collect")
            st.write("We collect information that you provide directly to us, including:")
            st.markdown("""
            - Account information (username, email)
            - Network scan data and results
            - System usage information
            """)

            st.subheader("2. How We Use Your Information")
            st.write("We use the information we collect to:")
            st.markdown("""
            - Provide and maintain our services
            - Monitor and analyze usage patterns
            - Protect against unauthorized access
            """)

            st.subheader("3. Data Security")
            st.write("We implement appropriate security measures to protect your information.")

            st.subheader("4. Contact Us")
            st.write("If you have questions about this Privacy Policy, please contact us.")
    
    with tab2:
        st.title("Terms of Service", help=None)
        
        with st.container():
            st.subheader("1. Acceptance of Terms")
            st.write("By accessing our service, you agree to these terms and conditions.")

            st.subheader("2. Use License")
            st.write("This tool should only be used on networks you own or have explicit permission to scan.")

            st.subheader("3. Disclaimer")
            st.markdown("""
            - The service is provided "as is" without warranties
            - We are not responsible for any damages from use of the service
            - Network scanning should comply with all applicable laws
            """)

            st.subheader("4. Limitations")
            st.write("You agree not to:")
            st.markdown("""
            - Use the service for illegal purposes
            - Scan networks without authorization
            - Attempt to breach or bypass security measures
            """)

            st.subheader("5. Governing Law")
            st.write("These terms shall be governed by and construed in accordance with applicable laws.")
    
    # Back button
    if st.button("← Back to Login", key="back_btn", type="secondary"):
        st.switch_page("login.py")

if __name__ == "__main__":
    privacy_and_terms() 