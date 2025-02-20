import streamlit as st

def privacy_policy_page():
    st.title("Privacy Policy")
    
    st.markdown("""
    ## Information Collection and Use
    
    ### Personal Information
    We collect the following information:
    - Username
    - Email address
    - Encrypted password
    
    ### Usage Data
    We collect data about how you use the Network Security Scanner.
    
    ## Data Storage
    - All personal data is encrypted
    - Passwords are hashed using secure algorithms
    - Data is stored in secure databases
    
    ## Data Sharing
    We do not share your personal information with third parties.
    
    ## Security Measures
    - Regular security audits
    - Encryption in transit and at rest
    - Regular backups
    
    ## Your Rights
    You have the right to:
    - Access your data
    - Request data deletion
    - Update your information
    
    ## Contact Us
    For privacy-related questions, contact our support team.
    """)
    
    if st.button("Back to Login"):
        st.session_state.pop('page', None)  # Clear the page state
        st.switch_page("login.py")

if __name__ == "__main__":
    privacy_policy_page() 