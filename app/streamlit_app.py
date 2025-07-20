import streamlit as st
import os
import re
import json
from datetime import datetime, timedelta
import bcrypt
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import pandas as pd
import plotly.graph_objects as go

# ===== ENVIRONMENT & SECURITY SETUP =====
import os
st.write(f"Streamlit bcrypt version: {bcrypt.__version__}")
st.write(f"Current working directory: {os.getcwd()}")
st.write(f"Files in current directory: {os.listdir('.')}")

load_dotenv()
FERNET_KEY_PATH = ".env.key"
if os.path.exists(FERNET_KEY_PATH):
    with open(FERNET_KEY_PATH, "rb") as f:
        key = f.read().strip()
        fernet = Fernet(key)
        for var in ["SMTP_PASS", "SMTP_USER", "APP_ACCESS_PASSWORD", "USER_ROLE"]:
            val = os.getenv(var)
            if val and val.startswith("enc::"):
                try:
                    decrypted = fernet.decrypt(val[5:].encode()).decode()
                    os.environ[var] = decrypted
                except Exception as e:
                    st.error(f"Failed to decrypt {var}: {e}")

ACCESS_PASSWORD = os.getenv("APP_ACCESS_PASSWORD")
USER_ROLE = st.session_state.get("user_role", "viewer")
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

USERS_FILE = "users.json"
FAILED_ATTEMPTS_FILE = "failed_attempts.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    with open("audit.log", "a") as log:
        log.write(f"[{datetime.now()}] Users updated\n")

def load_failed_attempts():
    if os.path.exists(FAILED_ATTEMPTS_FILE):
        with open(FAILED_ATTEMPTS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_failed_attempts(data):
    with open(FAILED_ATTEMPTS_FILE, "w") as f:
        json.dump(data, f)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

users = load_users()
failed_attempts = load_failed_attempts()

if not st.session_state.authenticated:
    st.title("🔐 Clinical Timeline App Login")
    login_tab, reset_tab = st.tabs(["Login", "Forgot Password"])

    with login_tab:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")        
        import random
        if username in failed_attempts and failed_attempts.get(username, {}).get("count", 0) >= 3:
            if "captcha_x" not in st.session_state:
                st.session_state.captcha_x = random.randint(1, 9)
                st.session_state.captcha_y = random.randint(1, 9)
            captcha_answer = st.text_input(
                f"CAPTCHA: What is {st.session_state.captcha_x} + {st.session_state.captcha_y}?",
                key="captcha"
            )

        if st.button("Login"):
            if username in failed_attempts and failed_attempts.get(username, {}).get("count", 0) >= 3:
                try:
                    if int(captcha_answer) != (st.session_state.captcha_x + st.session_state.captcha_y):
                        st.error("CAPTCHA incorrect. Please try again.")
                        st.session_state.captcha_x = random.randint(1, 9)
                        st.session_state.captcha_y = random.randint(1, 9)
                        st.stop()
                except:
                    st.error("CAPTCHA must be a number.")
                    st.stop()
            if username in users and bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.user_role = users[username]["role"]
                st.success("Access granted! Redirecting...")
                st.rerun()
            else:
                st.error("Invalid username or password")
                failed_attempts[username] = {
                    "count": failed_attempts.get(username, {"count": 0})["count"] + 1,
                    "last_attempt": datetime.now().isoformat()
                }
                save_failed_attempts(failed_attempts)
                with open("audit.log", "a") as log:
                    log.write(f"[{datetime.now()}] Failed login attempt for username: {username}\n")

    with reset_tab:
        reset_user = st.text_input("Enter your username to reset password")
        new_pass = st.text_input("Enter new password", type="password")
        if new_pass and (len(new_pass) < 8 or not re.search(r"[A-Z]", new_pass) or not re.search(r"[a-z]", new_pass) or not re.search(r"[0-9]", new_pass) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_pass)):
            st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        if st.button("Reset Password") and reset_user and reset_user in users and new_pass:
            users[reset_user]["password"] = hash_password(new_pass)
            save_users(users)
            st.success("Password reset successful. Please log in with your new password.")
            with open("audit.log", "a") as log:
                log.write(f"[{datetime.now()}] Password reset by user: {reset_user}\n")
    st.stop()

st.title("📊 Clinical Timeline App")
st.markdown("Welcome to the secured clinical timeline dashboard.")

# === ADVANCED TIMELINE PLOT ===
def plot_timeline():
    # Define inpatient stay data
    data = {
        "Stay": [1, 2, 3, 4, 5, 6],
        "Admission": [
            "2010-12-10",
            "2012-02-10",
            "2013-06-15",
            "2015-06-14",
            "2017-06-08",
            "2020-06-08"
        ],
        "Discharge": [
            "2011-02-21",
            "2012-04-28",
            "2013-09-19",
            "2015-09-19",
            "2017-09-19",
            "2020-09-19"
        ]
    }
    df = pd.DataFrame(data)
    df["Admission"] = pd.to_datetime(df["Admission"])
    df["Discharge"] = pd.to_datetime(df["Discharge"])

    # Define diagnosis and medication events
    illness_start = pd.to_datetime("2010-05-31")
    illness_end = illness_start + pd.DateOffset(years=15)
    initial_diagnosis_date = illness_start
    schizophrenia_dx_date = initial_diagnosis_date + timedelta(days=350)
    schizoaffective_dx_date = schizophrenia_dx_date + timedelta(days=386)

    medication_events = [
        (initial_diagnosis_date, "R 2 mg"),
        (pd.to_datetime("2010-12-11"), "R 3 mg"),
        (pd.to_datetime("2010-12-15"), "R 4 mg"),
    ]

    # Create figure
    fig = go.Figure()

    # Inpatient stays with duration labels
    for i, row in df.iterrows():
        fig.add_shape(
            type="rect",
            x0=row["Admission"],
            x1=row["Discharge"],
            y0=0.9,
            y1=1.1,
            line=dict(color="RoyalBlue"),
            fillcolor="LightSkyBlue",
            opacity=0.6
        )
        fig.add_annotation(
            x=row["Admission"] + (row["Discharge"] - row["Admission"]) / 2,
            y=1.15,
            text=f"Stay {row['Stay']} ({(row['Discharge'] - row['Admission']).days} days)",
            showarrow=False,
            font=dict(size=10)
        )

    # Illness trajectory line
    fig.add_trace(go.Scatter(
        x=[illness_start, illness_end],
        y=[1, 1],
        mode='lines',
        line=dict(color='black', width=2),
        name='Course of Illness',
        hoverinfo='skip'
    ))

    # Diagnosis annotations (abbreviated with arrows)
    diagnosis_arrows = [
        dict(x=initial_diagnosis_date, y=1.25, text="Dx: P-NOS", showarrow=True, arrowhead=2, ax=0, ay=-40, arrowcolor="darkred", font=dict(size=10, color="darkred")),
        dict(x=schizophrenia_dx_date, y=1.25, text="Dx: Sz", showarrow=True, arrowhead=2, ax=0, ay=-40, arrowcolor="darkred", font=dict(size=10, color="darkred")),
        dict(x=schizoaffective_dx_date, y=1.25, text="Dx: SAD", showarrow=True, arrowhead=2, ax=0, ay=-40, arrowcolor="darkred", font=dict(size=10, color="darkred")),
    ]

    # Medication annotations with arrows
    med_arrows = [
        dict(x=date, y=0.78, text=dose, showarrow=True, arrowhead=2, ax=0, ay=40, arrowcolor="darkgreen", font=dict(size=10, color="darkgreen"))
        for date, dose in medication_events
    ]

    # Legends
    med_legend = dict(
        xref="paper", yref="paper", x=0.01, y=-0.75,
        text="<b>Medication Legend:</b><br>R = Risperidone",
        showarrow=False, align="left",
        font=dict(size=11, color="darkgreen"),
        bordercolor="darkgreen", borderwidth=1,
        bgcolor="lightyellow"
    )

    diagnosis_legend = dict(
        xref="paper", yref="paper", x=0.3, y=-0.75,
        text="<b>Diagnosis Legend:</b><br>Dx: P-NOS = Psychosis NOS<br>Dx: Sz = Schizophrenia<br>Dx: SAD = Schizoaffective Disorder",
        showarrow=False, align="left",
        font=dict(size=11, color="darkred"),
        bordercolor="darkred", borderwidth=1,
        bgcolor="lavenderblush"
    )

    # Combine all annotations
    annotations = diagnosis_arrows + med_arrows + [med_legend, diagnosis_legend]

    # Final layout
    fig.update_layout(
        title="Course of Illness with Diagnoses, Medications, and Inpatient Stays",
        width=1000,
        height=520,
        xaxis_title="Date",
        yaxis=dict(visible=False, range=[0.7, 1.35]),
        xaxis=dict(
            range=[illness_start, illness_end],
            type='date',
            tickformat="%Y-%m-%d",
            showgrid=True,
            rangeslider=dict(visible=True),
            rangeselector=dict(buttons=[
                dict(count=6, label="6m", step="month", stepmode="backward"),
                dict(count=1, label="1y", step="year", stepmode="backward"),
                dict(count=5, label="5y", step="year", stepmode="backward"),
                dict(step="all")
            ])
        ),
        margin=dict(b=360),
        annotations=annotations,
        showlegend=False
    )

    return fig

st.subheader("Interactive Clinical Timeline")
st.plotly_chart(plot_timeline(), use_container_width=True)

if USER_ROLE.lower() == "admin":
    st.markdown("---")
    st.subheader("🛠 Admin Panel")

    if os.path.exists("audit.log"):
        with open("audit.log", "r") as log:
            st.text_area("Audit Log", log.read(), height=200)
        with open("audit.log", "rb") as f:
            st.download_button("Download Log", f, file_name="audit.log")
    else:
        st.info("No audit log available.")

    st.markdown("---")
    st.subheader("👥 User Role Management")

    users = load_users()
    usernames = list(users.keys())
    current_user = st.selectbox("Select a user to update:", usernames) if usernames else None

    if current_user:
        email = users.get(current_user, {}).get("email", "")
        new_email = st.text_input("Email for this user:", value=email, key="email_update")
        role = users.get(current_user, {}).get("role", "viewer")
        new_role = st.selectbox("Set role for this user:", ["admin", "viewer"], index=0 if role == "admin" else 1, key="role_update")
        if st.button("Update User Info"):
            users[current_user]["role"] = new_role
            users[current_user]["email"] = new_email
            save_users(users)
            with open("audit.log", "a") as log:
                log.write(f"[{datetime.now()}] Updated user info: {current_user}, role={new_role}, email={new_email}\n")
            st.success(f"Updated info for {current_user}")

    st.markdown("---")
    st.subheader("🔑 Admin Reset User Password")
    target_user = st.selectbox("Select a user to reset password:", [u for u in users.keys() if u != st.session_state.username], key="resetpw_user")
    new_admin_pass = st.text_input("New password for user", type="password", key="resetpw_val")
    if new_admin_pass and (len(new_admin_pass) < 8 or not re.search(r"[A-Z]", new_admin_pass) or not re.search(r"[a-z]", new_admin_pass) or not re.search(r"[0-9]", new_admin_pass) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_admin_pass)):
        st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
    if st.button("Reset Password", key="resetpw_btn") and target_user and new_admin_pass:
        users[target_user]["password"] = hash_password(new_admin_pass)
        save_users(users)
        st.success(f"Password for user '{target_user}' has been reset.")
        with open("audit.log", "a") as log:
            log.write(f"[{datetime.now()}] Admin reset password for user: {target_user}\n")

    st.markdown("---")
    st.subheader("🔓 Unlock Locked Accounts")
    failed_attempts = load_failed_attempts()
    locked_users = [user for user, info in failed_attempts.items() if info['count'] >= 5]
    if locked_users:
        unlock_user = st.selectbox("Select a user to unlock:", locked_users)
        if st.button("Unlock User"):
            if unlock_user in failed_attempts:
                del failed_attempts[unlock_user]
                save_failed_attempts(failed_attempts)
                st.success(f"{unlock_user} has been unlocked.")
                with open("audit.log", "a") as log:
                    log.write(f"[{datetime.now()}] Admin unlocked user: {unlock_user}\n")
    else:
        st.info("No locked users currently.")

    st.markdown("---")
    st.subheader("➕ Create New User")
    new_username = st.text_input("New username", key="newuser_name")
    new_email = st.text_input("New user's email", key="newuser_email")
    new_password = st.text_input("New password", type="password", key="newuser_pw")
    if new_password and (len(new_password) < 8 or not re.search(r"[A-Z]", new_password) or not re.search(r"[a-z]", new_password) or not re.search(r"[0-9]", new_password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password)):
        st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
    selected_role = st.selectbox("Role for new user", ["admin", "viewer"], key="newuser_role")
    if st.button("Create User", key="newuser_btn") and new_username and new_password and new_email:
        if new_username in users:
            st.warning("User already exists.")
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            st.warning("Please enter a valid email address.")
        else:
            users[new_username] = {
                "password": hash_password(new_password),
                "role": selected_role,
                "email": new_email
            }
            save_users(users)
            with open("audit.log", "a") as log:
                log.write(f"[{datetime.now()}] User created: {new_username} ({selected_role})\n")
            st.success(f"User '{new_username}' created with role '{selected_role}'")

if USER_ROLE.lower() == "viewer":
    st.subheader("📁 Viewer Dashboard")
    st.markdown("- View clinical timelines")
    st.markdown("- Export patient reports")
    st.info("Timeline visualizations coming soon...")
