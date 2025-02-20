import streamlit as st

def terms_page():
    st.title("Terms and Conditions")
    
    st.markdown("""
    ## 1. Acceptance of Terms
    By accessing and using the Network Security Scanner, you agree to be bound by these Terms and Conditions.
    
    ## 2. Use License
    Permission is granted to temporarily use the Network Security Scanner for personal, non-commercial transitory viewing only.
    
    ## 3. User Responsibilities
    - You must use the scanner responsibly and ethically
    - You agree to scan only networks you have permission to test
    - You will not use the tool for malicious purposes
    
    ## 4. Disclaimer
    The tool is provided "as is" without warranties of any kind.
    
    ## 5. Limitations
    We shall not be held liable for any damages arising from the use of the tool.
    
    ## 6. Revisions
    We reserve the right to update these terms at any time.
    """)
    
    if st.button("Back to Login"):
        st.session_state.pop('page', None)  # Clear the page state
        st.switch_page("login.py")

if __name__ == "__main__":
    terms_page() 