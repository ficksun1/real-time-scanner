import streamlit as st
import subprocess

def init_style():
    """Initialize custom styling"""
    with open('static/style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def run_nmap_command(command):
    """Run the Nmap command and return the output"""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"

def display_nmap_commands():
    init_style()
    
    st.title("Nmap Commands for Different Roles")
    
    # Role selection
    role = st.selectbox("Select Your Role", ["Select Role", "Developer", "Tester", "Security Analyst"])
    
    # Define Nmap commands for each role with descriptions
    commands = {
        "Developer": [
            ("Quick Scan", "nmap -sn <target>", "Performs a quick ping scan to discover live hosts."),
            ("Service Version Detection", "nmap -sV <target>", "Detects versions of services running on open ports."),
            ("Operating System Detection", "nmap -O <target>", "Attempts to determine the operating system of the target.")
        ],
        "Tester": [
            ("Full Port Scan", "nmap -p- <target>", "Scans all 65,535 ports on the target."),
            ("Aggressive Scan", "nmap -A <target>", "Performs an aggressive scan with OS detection, version detection, and script scanning."),
            ("Scan Specific Ports", "nmap -p 22,80,443 <target>", "Scans specific ports (22, 80, 443) on the target.")
        ],
        "Security Analyst": [
            ("Scan for Vulnerabilities", "nmap --script vuln <target>", "Scans for known vulnerabilities on the target."),
            ("Scan with Timing Template", "nmap -T4 <target>", "Sets the timing template to speed up the scan."),
            ("Scan Multiple Targets", "nmap <target1> <target2> <target3>", "Scans multiple targets at once.")
        ]
    }
    
    # Display commands based on selected role
    if role in commands:
        st.subheader(f"Commands for {role}")
        for cmd_name, cmd_template, description in commands[role]:
            st.markdown(f"**{cmd_name}**: {description}")
            target_ip = st.text_input(f"Enter target IP for '{cmd_name}' command", placeholder="e.g., 192.168.1.1")
            run_as_script = st.checkbox(f"Run '{cmd_name}' as a script")
            if st.button(f"Run {cmd_name}"):
                if target_ip:
                    command = cmd_template.replace("<target>", target_ip)
                    if run_as_script:
                        command = f"bash -c '{command}'"  # Format for script execution
                    output = run_nmap_command(command)
                    st.code(output)
                else:
                    st.error("Please enter a valid target IP address.")
    
if __name__ == "__main__":
    display_nmap_commands() 