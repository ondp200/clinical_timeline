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
from typing import Dict, Optional, List, Any
import random


class FileManager:
    """Handles all file I/O operations for the application."""
    
    def __init__(self, base_path: str = None):
        # Auto-detect base path based on current working directory
        if base_path is None:
            if os.path.exists("users.json"):
                # Running from app directory
                self.base_path = "."
            else:
                # Running from parent directory
                self.base_path = "app"
        else:
            self.base_path = base_path
            
        self.users_file = os.path.join(self.base_path, "users.json")
        self.failed_attempts_file = os.path.join(self.base_path, "failed_attempts.json")
        self.audit_log_file = os.path.join(self.base_path, "audit.log")
    
    def load_json(self, filename: str) -> Dict[str, Any]:
        """Load JSON data from file."""
        filepath = os.path.join(self.base_path, filename)
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                return json.load(f)
        return {}
    
    def save_json(self, data: Dict[str, Any], filename: str) -> None:
        """Save JSON data to file."""
        filepath = os.path.join(self.base_path, filename)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
    
    def load_users(self) -> Dict[str, Any]:
        """Load user data."""
        return self.load_json("users.json")
    
    def save_users(self, users: Dict[str, Any]) -> None:
        """Save user data."""
        self.save_json(users, "users.json")
    
    def load_failed_attempts(self) -> Dict[str, Any]:
        """Load failed login attempts."""
        return self.load_json("failed_attempts.json")
    
    def save_failed_attempts(self, attempts: Dict[str, Any]) -> None:
        """Save failed login attempts."""
        self.save_json(attempts, "failed_attempts.json")


class AuditLogger:
    """Handles audit logging operations."""
    
    def __init__(self, file_manager: FileManager):
        self.file_manager = file_manager
        self.log_file = file_manager.audit_log_file
    
    def log(self, message: str) -> None:
        """Write audit log entry."""
        with open(self.log_file, "a") as log:
            log.write(f"[{datetime.now()}] {message}\n")
    
    def get_log_content(self) -> str:
        """Read audit log content."""
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as log:
                return log.read()
        return ""
    
    def log_exists(self) -> bool:
        """Check if audit log exists."""
        return os.path.exists(self.log_file)


class PasswordValidator:
    """Handles password validation and hashing."""
    
    @staticmethod
    def is_valid_password(password: str) -> bool:
        """Validate password complexity."""
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode(), hashed.encode())


class AuthenticationService:
    """Handles user authentication and session management."""
    
    def __init__(self, file_manager: FileManager, audit_logger: AuditLogger):
        self.file_manager = file_manager
        self.audit_logger = audit_logger
        self.password_validator = PasswordValidator()
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return st.session_state.get("authenticated", False)
    
    def get_current_user(self) -> Optional[str]:
        """Get current authenticated user."""
        return st.session_state.get("username")
    
    def get_user_role(self) -> str:
        """Get current user's role."""
        return st.session_state.get("user_role", "viewer")
    
    def login(self, username: str, password: str) -> bool:
        """Attempt user login."""
        users = self.file_manager.load_users()
        failed_attempts = self.file_manager.load_failed_attempts()
        
        # Check if account is locked
        if self._is_account_locked(username, failed_attempts):
            return False
        
        # Verify credentials
        if username in users and self.password_validator.verify_password(password, users[username]["password"]):
            # Successful login
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.user_role = users[username]["role"]
            
            # Clear failed attempts
            if username in failed_attempts:
                del failed_attempts[username]
                self.file_manager.save_failed_attempts(failed_attempts)
            
            self.audit_logger.log(f"Successful login: {username}")
            return True
        else:
            # Failed login
            self._record_failed_attempt(username, failed_attempts)
            self.audit_logger.log(f"Failed login attempt for username: {username}")
            return False
    
    def _is_account_locked(self, username: str, failed_attempts: Dict[str, Any]) -> bool:
        """Check if account is locked due to failed attempts."""
        return username in failed_attempts and failed_attempts.get(username, {}).get("count", 0) >= 3
    
    def _record_failed_attempt(self, username: str, failed_attempts: Dict[str, Any]) -> None:
        """Record a failed login attempt."""
        failed_attempts[username] = {
            "count": failed_attempts.get(username, {"count": 0})["count"] + 1,
            "last_attempt": datetime.now().isoformat()
        }
        self.file_manager.save_failed_attempts(failed_attempts)
    
    def reset_password(self, username: str, new_password: str) -> bool:
        """Reset user password."""
        if not self.password_validator.is_valid_password(new_password):
            return False
        
        users = self.file_manager.load_users()
        if username not in users:
            return False
        
        users[username]["password"] = self.password_validator.hash_password(new_password)
        self.file_manager.save_users(users)
        self.audit_logger.log(f"Password reset by user: {username}")
        return True
    
    def needs_captcha(self, username: str) -> bool:
        """Check if user needs to solve CAPTCHA."""
        failed_attempts = self.file_manager.load_failed_attempts()
        return self._is_account_locked(username, failed_attempts)
    
    def logout(self) -> None:
        """Log out the current user and clear session."""
        username = self.get_current_user()
        if username:
            self.audit_logger.log(f"User logged out: {username}")
        
        # Clear all authentication-related session state
        st.session_state.authenticated = False
        st.session_state.username = None
        st.session_state.user_role = None
        
        # Clear any CAPTCHA state
        if "captcha_x" in st.session_state:
            del st.session_state.captcha_x
        if "captcha_y" in st.session_state:
            del st.session_state.captcha_y


class CaptchaManager:
    """Handles CAPTCHA generation and validation."""
    
    def __init__(self):
        if "captcha_x" not in st.session_state:
            self.generate_new_captcha()
    
    def generate_new_captcha(self) -> None:
        """Generate new CAPTCHA challenge."""
        st.session_state.captcha_x = random.randint(1, 9)
        st.session_state.captcha_y = random.randint(1, 9)
    
    def get_challenge(self) -> str:
        """Get CAPTCHA challenge text."""
        return f"What is {st.session_state.captcha_x} + {st.session_state.captcha_y}?"
    
    def validate(self, answer: str) -> bool:
        """Validate CAPTCHA answer."""
        try:
            return int(answer) == (st.session_state.captcha_x + st.session_state.captcha_y)
        except (ValueError, TypeError):
            return False


class TimelineVisualizer:
    """Handles clinical timeline visualization."""
    
    def create_timeline_plot(self) -> go.Figure:
        """Create the clinical timeline plot."""
        # Define inpatient stay data
        data = {
            "Stay": [1, 2, 3, 4, 5, 6],
            "Admission": [
                "2010-12-10", "2012-02-10", "2013-06-15",
                "2015-06-14", "2017-06-08", "2020-06-08"
            ],
            "Discharge": [
                "2011-02-21", "2012-04-28", "2013-09-19",
                "2015-09-19", "2017-09-19", "2020-09-19"
            ]
        }
        
        df = pd.DataFrame(data)
        df["Admission"] = pd.to_datetime(df["Admission"])
        df["Discharge"] = pd.to_datetime(df["Discharge"])
        
        # Define timeline events
        illness_start = pd.to_datetime("2010-05-31")
        illness_end = illness_start + pd.DateOffset(years=15)
        
        # Create figure
        fig = go.Figure()
        
        # Add inpatient stays
        self._add_inpatient_stays(fig, df)
        
        # Add illness trajectory
        self._add_illness_trajectory(fig, illness_start, illness_end)
        
        # Add annotations
        annotations = self._create_annotations(illness_start)
        
        # Configure layout
        self._configure_layout(fig, illness_start, illness_end, annotations)
        
        return fig
    
    def _add_inpatient_stays(self, fig: go.Figure, df: pd.DataFrame) -> None:
        """Add inpatient stay rectangles to the plot."""
        for i, row in df.iterrows():
            fig.add_shape(
                type="rect",
                x0=row["Admission"], x1=row["Discharge"],
                y0=0.9, y1=1.1,
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
    
    def _add_illness_trajectory(self, fig: go.Figure, start: pd.Timestamp, end: pd.Timestamp) -> None:
        """Add illness trajectory line."""
        fig.add_trace(go.Scatter(
            x=[start, end], y=[1, 1],
            mode='lines',
            line=dict(color='black', width=2),
            name='Course of Illness',
            hoverinfo='skip'
        ))
    
    def _create_annotations(self, illness_start: pd.Timestamp) -> List[Dict]:
        """Create diagnosis and medication annotations."""
        # Diagnosis events
        initial_diagnosis_date = illness_start
        schizophrenia_dx_date = initial_diagnosis_date + timedelta(days=350)
        schizoaffective_dx_date = schizophrenia_dx_date + timedelta(days=386)
        
        diagnosis_arrows = [
            dict(x=initial_diagnosis_date, y=1.25, text="Dx: P-NOS", 
                 showarrow=True, arrowhead=2, ax=0, ay=-40, 
                 arrowcolor="darkred", font=dict(size=10, color="darkred")),
            dict(x=schizophrenia_dx_date, y=1.25, text="Dx: Sz", 
                 showarrow=True, arrowhead=2, ax=0, ay=-40, 
                 arrowcolor="darkred", font=dict(size=10, color="darkred")),
            dict(x=schizoaffective_dx_date, y=1.25, text="Dx: SAD", 
                 showarrow=True, arrowhead=2, ax=0, ay=-40, 
                 arrowcolor="darkred", font=dict(size=10, color="darkred")),
        ]
        
        # Medication events
        medication_events = [
            (initial_diagnosis_date, "R 2 mg"),
            (pd.to_datetime("2010-12-11"), "R 3 mg"),
            (pd.to_datetime("2010-12-15"), "R 4 mg"),
        ]
        
        med_arrows = [
            dict(x=date, y=0.78, text=dose, 
                 showarrow=True, arrowhead=2, ax=0, ay=40, 
                 arrowcolor="darkgreen", font=dict(size=10, color="darkgreen"))
            for date, dose in medication_events
        ]
        
        # Legends
        legends = [
            dict(xref="paper", yref="paper", x=0.01, y=-0.75,
                 text="<b>Medication Legend:</b><br>R = Risperidone",
                 showarrow=False, align="left",
                 font=dict(size=11, color="darkgreen"),
                 bordercolor="darkgreen", borderwidth=1,
                 bgcolor="lightyellow"),
            dict(xref="paper", yref="paper", x=0.3, y=-0.75,
                 text="<b>Diagnosis Legend:</b><br>Dx: P-NOS = Psychosis NOS<br>Dx: Sz = Schizophrenia<br>Dx: SAD = Schizoaffective Disorder",
                 showarrow=False, align="left",
                 font=dict(size=11, color="darkred"),
                 bordercolor="darkred", borderwidth=1,
                 bgcolor="lavenderblush")
        ]
        
        return diagnosis_arrows + med_arrows + legends
    
    def _configure_layout(self, fig: go.Figure, start: pd.Timestamp, end: pd.Timestamp, annotations: List[Dict]) -> None:
        """Configure the plot layout."""
        fig.update_layout(
            title="Course of Illness with Diagnoses, Medications, and Inpatient Stays",
            width=1000, height=520,
            xaxis_title="Date",
            yaxis=dict(visible=False, range=[0.7, 1.35]),
            xaxis=dict(
                range=[start, end],
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


class LoginPage:
    """Handles the login page UI."""
    
    def __init__(self, auth_service: AuthenticationService):
        self.auth_service = auth_service
        self.captcha_manager = CaptchaManager()
    
    def render(self) -> None:
        """Render the login page."""
        st.title("🔐 Clinical Timeline App Login")
        login_tab, reset_tab = st.tabs(["Login", "Forgot Password"])
        
        with login_tab:
            self._render_login_tab()
        
        with reset_tab:
            self._render_reset_tab()
    
    def _render_login_tab(self) -> None:
        """Render the login tab."""
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        # Show CAPTCHA if needed
        captcha_answer = None
        if username and self.auth_service.needs_captcha(username):
            captcha_answer = st.text_input(
                f"CAPTCHA: {self.captcha_manager.get_challenge()}",
                key="captcha"
            )
        
        if st.button("Login"):
            # Validate CAPTCHA if required
            if username and self.auth_service.needs_captcha(username):
                if not captcha_answer or not self.captcha_manager.validate(captcha_answer):
                    st.error("CAPTCHA incorrect. Please try again.")
                    self.captcha_manager.generate_new_captcha()
                    st.stop()
            
            # Attempt login
            if self.auth_service.login(username, password):
                st.success("Access granted! Redirecting...")
                st.rerun()
            else:
                st.error("Invalid username or password")
    
    def _render_reset_tab(self) -> None:
        """Render the password reset tab."""
        reset_user = st.text_input("Enter your username to reset password")
        new_pass = st.text_input("Enter new password", type="password")
        
        if new_pass and not PasswordValidator.is_valid_password(new_pass):
            st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        
        if st.button("Reset Password") and reset_user and new_pass:
            if self.auth_service.reset_password(reset_user, new_pass):
                st.success("Password reset successful. Please log in with your new password.")
            else:
                st.error("Password reset failed. Please check your username and password requirements.")


class AdminPanel:
    """Handles the admin panel UI."""
    
    def __init__(self, file_manager: FileManager, audit_logger: AuditLogger, auth_service: AuthenticationService):
        self.file_manager = file_manager
        self.audit_logger = audit_logger
        self.auth_service = auth_service
        self.password_validator = PasswordValidator()
    
    def render(self) -> None:
        """Render the admin panel."""
        if self.auth_service.get_user_role().lower() != "admin":
            return
        
        st.markdown("---")
        st.subheader("🛠 Admin Panel")
        
        self._render_audit_log_section()
        self._render_user_management_section()
        self._render_password_reset_section()
        self._render_unlock_accounts_section()
        self._render_create_user_section()
    
    def _render_audit_log_section(self) -> None:
        """Render audit log section."""
        if self.audit_logger.log_exists():
            log_content = self.audit_logger.get_log_content()
            st.text_area("Audit Log", log_content, height=200)
            st.download_button("Download Log", log_content.encode(), file_name="audit.log")
        else:
            st.info("No audit log available.")
    
    def _render_user_management_section(self) -> None:
        """Render user role management section."""
        st.markdown("---")
        st.subheader("👥 User Role Management")
        
        users = self.file_manager.load_users()
        usernames = list(users.keys())
        current_user = st.selectbox("Select a user to update:", usernames) if usernames else None
        
        if current_user:
            user_data = users.get(current_user, {})
            email = user_data.get("email", "")
            role = user_data.get("role", "viewer")
            
            new_email = st.text_input("Email for this user:", value=email, key="email_update")
            new_role = st.selectbox("Set role for this user:", ["admin", "viewer"], 
                                  index=0 if role == "admin" else 1, key="role_update")
            
            if st.button("Update User Info"):
                users[current_user]["role"] = new_role
                users[current_user]["email"] = new_email
                self.file_manager.save_users(users)
                self.audit_logger.log(f"Updated user info: {current_user}, role={new_role}, email={new_email}")
                st.success(f"Updated info for {current_user}")
    
    def _render_password_reset_section(self) -> None:
        """Render admin password reset section."""
        st.markdown("---")
        st.subheader("🔑 Admin Reset User Password")
        
        users = self.file_manager.load_users()
        current_username = self.auth_service.get_current_user()
        other_users = [u for u in users.keys() if u != current_username]
        
        target_user = st.selectbox("Select a user to reset password:", other_users, key="resetpw_user")
        new_admin_pass = st.text_input("New password for user", type="password", key="resetpw_val")
        
        if new_admin_pass and not self.password_validator.is_valid_password(new_admin_pass):
            st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        
        if st.button("Reset Password", key="resetpw_btn") and target_user and new_admin_pass:
            users[target_user]["password"] = self.password_validator.hash_password(new_admin_pass)
            self.file_manager.save_users(users)
            st.success(f"Password for user '{target_user}' has been reset.")
            self.audit_logger.log(f"Admin reset password for user: {target_user}")
    
    def _render_unlock_accounts_section(self) -> None:
        """Render unlock accounts section."""
        st.markdown("---")
        st.subheader("🔓 Unlock Locked Accounts")
        
        failed_attempts = self.file_manager.load_failed_attempts()
        locked_users = [user for user, info in failed_attempts.items() if info['count'] >= 5]
        
        if locked_users:
            unlock_user = st.selectbox("Select a user to unlock:", locked_users)
            if st.button("Unlock User"):
                if unlock_user in failed_attempts:
                    del failed_attempts[unlock_user]
                    self.file_manager.save_failed_attempts(failed_attempts)
                    st.success(f"{unlock_user} has been unlocked.")
                    self.audit_logger.log(f"Admin unlocked user: {unlock_user}")
        else:
            st.info("No locked users currently.")
    
    def _render_create_user_section(self) -> None:
        """Render create new user section."""
        st.markdown("---")
        st.subheader("➕ Create New User")
        
        new_username = st.text_input("New username", key="newuser_name")
        new_email = st.text_input("New user's email", key="newuser_email")
        new_password = st.text_input("New password", type="password", key="newuser_pw")
        
        if new_password and not self.password_validator.is_valid_password(new_password):
            st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        
        selected_role = st.selectbox("Role for new user", ["admin", "viewer"], key="newuser_role")
        
        if st.button("Create User", key="newuser_btn") and new_username and new_password and new_email:
            users = self.file_manager.load_users()
            
            if new_username in users:
                st.warning("User already exists.")
            elif not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                st.warning("Please enter a valid email address.")
            else:
                users[new_username] = {
                    "password": self.password_validator.hash_password(new_password),
                    "role": selected_role,
                    "email": new_email
                }
                self.file_manager.save_users(users)
                self.audit_logger.log(f"User created: {new_username} ({selected_role})")
                st.success(f"User '{new_username}' created with role '{selected_role}'")


class ViewerDashboard:
    """Handles the viewer dashboard UI."""
    
    def render(self) -> None:
        """Render the viewer dashboard."""
        st.subheader("📁 Viewer Dashboard")
        st.markdown("- View clinical timelines")
        st.markdown("- Export patient reports")
        st.info("Timeline visualizations coming soon...")


class EnvironmentSetup:
    """Handles environment and security setup."""
    
    @staticmethod
    def setup() -> None:
        """Initialize environment setup."""
        load_dotenv()
        EnvironmentSetup._setup_encryption()
        EnvironmentSetup._initialize_session_state()
    
    @staticmethod
    def _setup_encryption() -> None:
        """Setup Fernet encryption for environment variables."""
        fernet_key_path = ".env.key"
        if os.path.exists(fernet_key_path):
            with open(fernet_key_path, "rb") as f:
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
    
    @staticmethod
    def _initialize_session_state() -> None:
        """Initialize Streamlit session state."""
        if "authenticated" not in st.session_state:
            st.session_state.authenticated = False


class ClinicalTimelineApp:
    """Main application orchestrator."""
    
    def __init__(self):
        EnvironmentSetup.setup()
        
        # Initialize services
        self.file_manager = FileManager()
        self.audit_logger = AuditLogger(self.file_manager)
        self.auth_service = AuthenticationService(self.file_manager, self.audit_logger)
        self.timeline_visualizer = TimelineVisualizer()
        
        # Initialize UI components
        self.login_page = LoginPage(self.auth_service)
        self.admin_panel = AdminPanel(self.file_manager, self.audit_logger, self.auth_service)
        self.viewer_dashboard = ViewerDashboard()
    
    def run(self) -> None:
        """Run the application."""
        # Debug info (remove in production)
        st.write(f"Streamlit bcrypt version: {bcrypt.__version__}")
        st.write(f"Current working directory: {os.getcwd()}")
        st.write(f"Files in current directory: {os.listdir('.')}")
        
        # Check authentication
        if not self.auth_service.is_authenticated():
            self.login_page.render()
            st.stop()
        
        # Main application
        self._render_main_app()
    
    def _render_main_app(self) -> None:
        """Render the main application interface."""
        # Header with logout functionality
        col1, col2 = st.columns([3, 1])
        with col1:
            st.title("📊 Clinical Timeline App")
        with col2:
            current_user = self.auth_service.get_current_user()
            user_role = self.auth_service.get_user_role()
            st.write(f"👤 **{current_user}** ({user_role})")
            if st.button("🚪 Logout", key="logout_btn"):
                self.auth_service.logout()
                st.rerun()
        
        st.markdown("Welcome to the secured clinical timeline dashboard.")
        
        # Timeline visualization
        st.subheader("Interactive Clinical Timeline")
        timeline_fig = self.timeline_visualizer.create_timeline_plot()
        st.plotly_chart(timeline_fig, use_container_width=True)
        
        # Role-specific sections
        user_role = self.auth_service.get_user_role()
        if user_role.lower() == "admin":
            self.admin_panel.render()
        elif user_role.lower() == "viewer":
            self.viewer_dashboard.render()


# Application entry point
if __name__ == "__main__":
    app = ClinicalTimelineApp()
    app.run()