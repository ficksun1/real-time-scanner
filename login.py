import streamlit as st
import extra_streamlit_components as stx
from auth import AuthManager, DatabaseManager
from datetime import datetime, timedelta

# Move this outside of any function, at the very top of your script
st.set_page_config(
    page_title="Network Scanner Login",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'token' not in st.session_state:
    st.session_state.token = None

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def nav_to_privacy():
    st.session_state.nav = 'privacy'
    st.rerun()

def nav_to_terms():
    st.session_state.nav = 'terms'
    st.rerun()

def login_page():
    init_style()
    
    # Create cookie manager
    cookie_manager = stx.CookieManager()

    # Container for centered content
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Logo and Title
        st.markdown("""
            <div style='text-align: center; padding: 2rem;'>
                <div class='login-logo-container'>
                    <svg width="100" height="100" viewBox="0 0 200 200">
                        <defs>
                            <linearGradient id="cyber-gradient">
                                <stop offset="0%" stop-color="#ff2a6d">
                                    <animate attributeName="stop-color" values="#ff2a6d;#05d9e8;#ff2a6d" dur="4s" repeatCount="indefinite" />
                                </stop>
                                <stop offset="100%" stop-color="#05d9e8">
                                    <animate attributeName="stop-color" values="#05d9e8;#ff2a6d;#05d9e8" dur="4s" repeatCount="indefinite" />
                                </stop>
                            </linearGradient>
                        </defs>
                        <path d="M100,20 L160,50 L160,150 L100,180 L40,150 L40,50 Z" fill="none" stroke="url(#cyber-gradient)" stroke-width="4"/>
                        <path d="M100,40 L140,60 L140,140 L100,160 L60,140 L60,60 Z" fill="none" stroke="#ff71ce" stroke-width="2"/>
                        <circle cx="100" cy="100" r="30" fill="none" stroke="#00ff9f" stroke-width="3"/>
                    </svg>
                </div>
                <h1 class='login-title'>Network Security Scanner</h1>
            </div>
        """, unsafe_allow_html=True)
        
        # Create tabs with custom styling
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
        
        auth_manager = AuthManager()

        with tab1:
            with st.form("login_form"):
                st.markdown("<h3 style='text-align: center; color: #d1f7ff;'>Welcome Back!</h3>", unsafe_allow_html=True)
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                remember_me = st.checkbox("Remember me")
                
                submit_login = st.form_submit_button("Login", use_container_width=True)
                if submit_login:
                    handle_login(username, password, remember_me, auth_manager, cookie_manager)

        with tab2:
            with st.form("register_form"):
                st.markdown("<h3 style='text-align: center; color: #d1f7ff;'>Create Account</h3>", unsafe_allow_html=True)
                new_username = st.text_input("Username")
                new_email = st.text_input("Email")
                new_password = st.text_input("Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                
                if new_password:
                    strength = check_password_strength(new_password)
                    st.progress(strength[0])
                    st.caption(strength[1])
                
                terms = st.checkbox("I agree to the Terms and Conditions")
                submit_register = st.form_submit_button("Register", use_container_width=True)

                if submit_register:
                    handle_registration(new_username, new_email, new_password, 
                                     confirm_password, terms, auth_manager)

        # Footer with links
        st.markdown("---")
        
        # Center column for footer content
        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            st.markdown(
                "<div style='text-align: center; color: #d1f7ff;'>"
                "© 2025 Network Scanner. All rights reserved.</div>",
                unsafe_allow_html=True
            )
            
            # Simple horizontal layout for links
            st.markdown(
                "<div style='display: flex; justify-content: center; gap: 20px; margin-top: 10px;'>"
                "<button onclick='nav_to_privacy()' style='background: none; border: none; color: #05d9e8; cursor: pointer;'>Privacy Policy</button>"
                "<span style='color: #05d9e8;'>•</span>"
                "<button onclick='nav_to_terms()' style='background: none; border: none; color: #05d9e8; cursor: pointer;'>Terms of Service</button>"
                "</div>",
                unsafe_allow_html=True
            )

        if st.session_state.logged_in:
            st.switch_page("pages/scanner.py")

        # Handle navigation
        if 'nav' not in st.session_state:
            st.session_state.nav = None

        if st.session_state.nav == 'privacy':
            st.session_state.nav = None
            st.switch_page("pages/privacy_policy.py")
        elif st.session_state.nav == 'terms':
            st.session_state.nav = None
            st.switch_page("pages/terms.py")

def handle_login(username, password, remember_me, auth_manager, cookie_manager):
    if not username or not password:
        st.error("Please fill in all fields")
        return
    
    user = auth_manager.db.verify_user(username, password)
    if user:
        token = auth_manager.create_token(user['id'])
        if remember_me:
            # Set expiration to 30 days from now
            expiry = datetime.now() + timedelta(days=30)
            cookie_manager.set('token', token, expires_at=expiry)
        st.session_state.token = token
        st.session_state.user_id = user['id']
        st.session_state.username = user['username']
        st.session_state.logged_in = True
        st.success("Login successful!")
        st.rerun()
    else:
        st.error("Invalid username or password")

def handle_registration(username, email, password, confirm_password, terms, auth_manager):
    if not all([username, email, password, confirm_password]):
        st.error("Please fill in all fields")
    elif not terms:
        st.error("Please accept the Terms and Conditions")
    elif password != confirm_password:
        st.error("Passwords do not match")
    elif len(password) < 6:
        st.error("Password must be at least 6 characters long")
    else:
        if auth_manager.db.create_user(username, password, email):
            st.success("Registration successful! Please login.")
        else:
            st.error("Username or email already exists")

def check_password_strength(password):
    """Returns (strength_percentage, message)"""
    strength = 0
    messages = []
    
    if len(password) >= 8:
        strength += 25
        messages.append("Length ✓")
    if any(c.isupper() for c in password):
        strength += 25
        messages.append("Uppercase ✓")
    if any(c.islower() for c in password):
        strength += 25
        messages.append("Lowercase ✓")
    if any(c.isdigit() for c in password):
        strength += 25
        messages.append("Number ✓")
        
    return (strength/100, " ".join(messages))

if __name__ == "__main__":
    login_page() 