"""Login page - pure UI components, no business logic."""
import streamlit as st
from ..services import AuthenticationService, CaptchaService
from ..models import AuthenticationResult


class LoginPage:
    """Login page UI - delegates all business logic to services."""
    
    def __init__(self, auth_service: AuthenticationService, captcha_service: CaptchaService):
        self.auth_service = auth_service
        self.captcha_service = captcha_service
    
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
            captcha_answer = self._render_captcha()
        
        if st.button("Login"):
            self._handle_login(username, password, captcha_answer)
    
    def _render_captcha(self) -> str:
        """Render CAPTCHA challenge."""
        # Initialize CAPTCHA in session state if needed
        if "captcha_x" not in st.session_state:
            st.session_state.captcha_x, st.session_state.captcha_y = self.captcha_service.generate_challenge()
        
        challenge_text = self.captcha_service.get_challenge_text(
            st.session_state.captcha_x, 
            st.session_state.captcha_y
        )
        
        return st.text_input(f"CAPTCHA: {challenge_text}", key="captcha")
    
    def _handle_login(self, username: str, password: str, captcha_answer: str = None) -> None:
        """Handle login attempt."""
        # Validate CAPTCHA if required
        if username and self.auth_service.needs_captcha(username):
            if not captcha_answer or not self.captcha_service.validate_answer(
                st.session_state.captcha_x, 
                st.session_state.captcha_y, 
                captcha_answer
            ):
                st.error("CAPTCHA incorrect. Please try again.")
                # Generate new CAPTCHA
                st.session_state.captcha_x, st.session_state.captcha_y = self.captcha_service.generate_challenge()
                return
        
        # Attempt authentication
        result: AuthenticationResult = self.auth_service.authenticate(username, password)
        
        if result.success:
            # Store user in session state
            st.session_state.authenticated = True
            st.session_state.current_user = result.user
            st.success("Access granted! Redirecting...")
            st.rerun()
        else:
            st.error(result.error_message or "Login failed")
            if result.requires_captcha:
                # Generate new CAPTCHA for next attempt
                st.session_state.captcha_x, st.session_state.captcha_y = self.captcha_service.generate_challenge()
    
    def _render_reset_tab(self) -> None:
        """Render the password reset tab."""
        reset_user = st.text_input("Enter your username to reset password")
        new_pass = st.text_input("Enter new password", type="password")
        
        # Show password validation
        if new_pass:
            from ..services import PasswordService
            if not PasswordService.is_valid_password(new_pass):
                st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        
        if st.button("Reset Password") and reset_user and new_pass:
            if self.auth_service.reset_password(reset_user, new_pass):
                st.success("Password reset successful. Please log in with your new password.")
            else:
                st.error("Password reset failed. Please check your username and password requirements.")