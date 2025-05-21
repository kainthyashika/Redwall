import streamlit as st
import pandas as pd
import datetime
import random
import altair as alt
import sqlite3

# ---------------- Database Setup ----------------
conn = sqlite3.connect('hactza_logs.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    time TEXT,
    role TEXT,
    context TEXT,
    device TEXT,
    region TEXT,
    risk INTEGER,
    decision TEXT,
    mfa TEXT,
    ip TEXT
)
''')
conn.commit()

# ----------------- SESSION STATE -----------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None

# ----------------- LOGIN SCREEN -----------------
def login_screen():
    st.title("HACTZA Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Login as", ["Admin", "User"])

    if st.button("Login"):
        if username and password:
            if (role == "Admin" and username == "admin" and password == "admin123") or \
               (role == "User" and username == "user" and password == "user123"):
                st.session_state.authenticated = True
                st.session_state.role = role
                st.success(f"Logged in as {role}")
            else:
                st.error("Invalid credentials")
        else:
            st.error("Please enter username and password")

if not st.session_state.authenticated:
    login_screen()
    st.stop()

# ----------------- SIDEBAR NAV -----------------
st.sidebar.header("Navigation")
view = st.sidebar.radio("Go to", ["Access Request", "Admin Dashboard", "Custom Rule Engine", "IP Reputation Check"])
if st.sidebar.button("Logout"):
    st.session_state.update({"authenticated": False, "role": None})
    st.experimental_rerun()

# ----------------- THREAT FEED -----------------
threat_feed = [
    {"IP": "192.168.5.45", "Severity": "High", "Threat": "Ransomware"},
    {"IP": "10.0.2.15", "Severity": "Medium", "Threat": "Brute Force Login"},
    {"IP": "203.0.113.12", "Severity": "Critical", "Threat": "Suspicious Lateral Movement"}
]

# ----------------- FUNCTIONS -----------------
def compute_risk_score(user_role, context, device_trust, region, mfa_passed):
    score = 0
    score += {"Admin": 10, "User": 30, "Guest": 50}.get(user_role, 50)
    score += {"Secure Network": 10, "VPN": 20, "Unsecure Network": 40, "Public WiFi": 50}.get(context, 50)
    score += {"Trusted": 10, "Unknown": 30, "Compromised": 50}.get(device_trust, 50)
    score += {"India": 10, "USA": 15, "Russia": 35, "China": 40, "Other": 25}.get(region, 25)
    if not mfa_passed:
        score += 30
    score += random.randint(-5, 5)
    return min(100, max(0, score))

def access_decision(score):
    if score < 40:
        return "Access Granted"
    elif score < 70:
        return "Access Limited"
    else:
        return "Access Denied"

def save_log(time, role, context, device, region, risk, decision, mfa, ip):
    c.execute('''
    INSERT INTO logs (time, role, context, device, region, risk, decision, mfa, ip)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (time, role, context, device, region, risk, decision, mfa, ip))
    conn.commit()

def get_logs():
    df = pd.read_sql_query('SELECT * FROM logs', conn)
    return df

# ----------------- ACCESS REQUEST -----------------
if view == "Access Request":
    st.title("HACTZA Access Request")

    user_role = st.selectbox("User Role", ["Admin", "User", "Guest"])
    context = st.selectbox("Network Context", ["Secure Network", "VPN", "Unsecure Network", "Public WiFi"])
    device_trust = st.selectbox("Device Trust Level", ["Trusted", "Unknown", "Compromised"])
    region = st.selectbox("Login Region", ["India", "USA", "Russia", "China", "Other"])
    ip_address = st.text_input("Your IP Address", value="127.0.0.1")
    mfa_code = st.text_input("Enter MFA Code", type="password")

    if st.button("Check Access"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mfa_passed = (mfa_code == "123456")
        risk = compute_risk_score(user_role, context, device_trust, region, mfa_passed)
        decision = access_decision(risk)

        if risk >= 70:
            st.error(f"ALERT: High-Risk Access Attempt (Score: {risk})")
        elif risk >= 40:
            st.warning(f"Limited Access (Score: {risk})")
        else:
            st.success(f"Access Approved (Score: {risk})")

        save_log(timestamp, user_role, context, device_trust, region, risk, decision, "Passed" if mfa_passed else "Failed", ip_address)

        if decision == "Access Denied":
            st.warning(f"* ALERT SENT TO ADMIN: High risk access attempt from IP {ip_address} *")

# ----------------- ADMIN DASHBOARD -----------------
elif view == "Admin Dashboard":
    if st.session_state.role != "Admin":
        st.warning("Admin access required.")
        st.stop()

    st.title("Admin Dashboard")
    df = get_logs()

    if not df.empty:
        st.subheader("Access Logs")
        st.dataframe(df.drop(columns=["id"]), use_container_width=True)
        st.download_button("Download Logs as CSV", df.to_csv(index=False).encode("utf-8"), "hactza_logs.csv", "text/csv")

        denied = df[df["decision"] == "Access Denied"].shape[0]
        granted = df[df["decision"] == "Access Granted"].shape[0]
        limited = df[df["decision"] == "Access Limited"].shape[0]
        st.markdown(f"*Granted:* {granted} | *Limited:* {limited} | *Denied:* {denied}")

        st.subheader("Risk Distribution")
        df["Risk Level"] = pd.cut(df["risk"], bins=[0, 40, 70, 100], labels=["Low", "Medium", "High"])
        chart_data = df["Risk Level"].value_counts().reset_index()
        chart_data.columns = ["Risk Level", "Count"]

        chart = alt.Chart(chart_data).mark_bar().encode(
            x='Risk Level',
            y='Count',
            color='Risk Level',
            tooltip=['Risk Level', 'Count']
        ).properties(width=400)
        st.altair_chart(chart)

    else:
        st.info("No logs yet.")

    st.subheader("Simulated Threat Feed")
    threat_df = pd.DataFrame(threat_feed)
    st.dataframe(threat_df)

# ----------------- CUSTOM RULE ENGINE -----------------
elif view == "Custom Rule Engine":
    st.title("Custom Rule Engine")
    role = st.selectbox("If user role is", ["Admin", "User", "Guest"])
    network = st.selectbox("And network is", ["Secure Network", "VPN", "Public WiFi"])
    device = st.selectbox("And device is", ["Trusted", "Unknown", "Compromised"])
    action = st.selectbox("Then", ["Grant Access", "Limit Access", "Deny Access"])

    if st.button("Simulate Apply Rule"):
        st.success(f"Rule: If {role} using {network} on {device} device → {action}")

# ----------------- IP REPUTATION CHECK -----------------
elif view == "IP Reputation Check":
    st.title("IP Reputation Check (Offline Mode)")

    ip = st.text_input("Enter IP address to check", "127.0.0.1")
    st.warning("This feature is disabled in offline mode. Connect to the internet and integrate AbuseIPDB or similar APIs.")
