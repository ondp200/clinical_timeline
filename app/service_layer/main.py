"""Main entry point for service layer architecture Clinical Timeline App."""
import streamlit as st
import os
import bcrypt
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Import all our layers
from .repositories import UserRepository, FailedAttemptsRepository, AuditRepository
from .services import (
    AuthenticationService, 
    TimelineDataService, 
    TimelineVisualizationService,
    CaptchaService
)
from .pages import LoginPage, TimelinePage, AdminPage, ViewerPage
from .models import User


class ApplicationConfig:
    """Application configuration and environment setup."""
    
    @staticmethod
    def setup_environment() -> None:
        """Initialize environment setup."""
        load_dotenv()
        ApplicationConfig._setup_encryption()
        ApplicationConfig._initialize_session_state()
    
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
        if "current_user" not in st.session_state:
            st.session_state.current_user = None


class ServiceContainer:
    """Dependency injection container for services."""
    
    def __init__(self):
        # Initialize repositories (data layer)
        self.user_repo = UserRepository()
        self.failed_attempts_repo = FailedAttemptsRepository()
        self.audit_repo = AuditRepository()
        
        # Initialize services (business logic layer)
        self.auth_service = AuthenticationService(
            self.user_repo, 
            self.failed_attempts_repo, 
            self.audit_repo
        )
        self.timeline_data_service = TimelineDataService()
        self.timeline_viz_service = TimelineVisualizationService()
        self.captcha_service = CaptchaService()
        
        # Initialize pages (UI layer)
        self.login_page = LoginPage(self.auth_service, self.captcha_service)
        self.timeline_page = TimelinePage(self.timeline_data_service, self.timeline_viz_service)
        self.admin_page = AdminPage(self.auth_service, self.audit_repo)
        self.viewer_page = ViewerPage()


class ClinicalTimelineApp:
    """Main application orchestrator using service layer architecture."""
    
    def __init__(self):
        ApplicationConfig.setup_environment()
        self.services = ServiceContainer()
    
    def run(self) -> None:
        """Run the application."""
        # Debug info (remove in production)
        self._render_debug_info()
        
        # Check authentication
        if not self._is_authenticated():
            self.services.login_page.render()
            st.stop()
        
        # Main application
        self._render_main_app()
    
    def _render_debug_info(self) -> None:
        """Render debug information."""
        st.write(f"Streamlit bcrypt version: {bcrypt.__version__}")
        st.write(f"Current working directory: {os.getcwd()}")
        st.write(f"Files in current directory: {os.listdir('.')}")
    
    def _is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return st.session_state.get("authenticated", False)
    
    def _get_current_user(self) -> User:
        """Get current authenticated user."""
        return st.session_state.get("current_user")
    
    def _render_main_app(self) -> None:
        """Render the main application interface."""
        current_user = self._get_current_user()
        
        # Header with logout functionality
        self._render_header(current_user)
        
        st.markdown("Welcome to the secured clinical timeline dashboard.")
        
        # Timeline visualization (available to all authenticated users)
        self.services.timeline_page.render()
        
        # Role-specific sections
        if current_user and current_user.is_admin():
            self.services.admin_page.render(current_user)
        elif current_user and current_user.is_viewer():
            self.services.viewer_page.render()
    
    def _render_header(self, current_user: User) -> None:
        """Render application header with user info and logout."""
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.title("📊 Clinical Timeline App")
        
        with col2:
            if current_user:
                st.write(f"👤 **{current_user.username}** ({current_user.role})")
                if st.button("🚪 Logout", key="logout_btn"):
                    self._logout()
    
    def _logout(self) -> None:
        """Handle user logout."""
        current_user = self._get_current_user()
        if current_user:
            self.services.audit_repo.log_event(f"User logged out: {current_user.username}")
        
        # Clear session state
        st.session_state.authenticated = False
        st.session_state.current_user = None
        
        # Clear CAPTCHA state if present
        for key in ["captcha_x", "captcha_y"]:
            if key in st.session_state:
                del st.session_state[key]
        
        st.rerun()


def main():
    """Application entry point."""
    app = ClinicalTimelineApp()
    app.run()


if __name__ == "__main__":
    main()