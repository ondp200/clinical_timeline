"""Admin page - pure UI components for administrative functions."""
import streamlit as st
from ..services import AuthenticationService
from ..repositories import AuditRepository


class AdminPage:
    """Admin panel UI - delegates all business logic to services."""
    
    def __init__(self, auth_service: AuthenticationService, audit_repo: AuditRepository):
        self.auth_service = auth_service
        self.audit_repo = audit_repo
    
    def render(self, current_user) -> None:
        """Render the admin panel."""
        if not current_user or not current_user.is_admin():
            return
        
        st.markdown("---")
        st.subheader("🛠 Admin Panel")
        
        self._render_audit_log_section()
        self._render_user_management_section()
        self._render_password_reset_section(current_user)
        self._render_unlock_accounts_section(current_user)
        self._render_create_user_section()
    
    def _render_audit_log_section(self) -> None:
        """Render audit log section."""
        if self.audit_repo.log_exists():
            log_content = self.audit_repo.get_log_content()
            st.text_area("Audit Log", log_content, height=200)
            st.download_button("Download Log", log_content.encode(), file_name="audit.log")
        else:
            st.info("No audit log available.")
    
    def _render_user_management_section(self) -> None:
        """Render user role management section."""
        st.markdown("---")
        st.subheader("👥 User Role Management")
        
        all_users = self.auth_service.get_all_users()
        usernames = list(all_users.keys())
        current_user_selection = st.selectbox("Select a user to update:", usernames) if usernames else None
        
        if current_user_selection:
            user_data = all_users[current_user_selection]
            email = user_data.get("email", "")
            role = user_data.get("role", "viewer")
            
            new_email = st.text_input("Email for this user:", value=email, key="email_update")
            new_role = st.selectbox("Set role for this user:", ["admin", "viewer"], 
                                  index=0 if role == "admin" else 1, key="role_update")
            
            if st.button("Update User Info"):
                if self.auth_service.update_user(current_user_selection, new_email, new_role):
                    st.success(f"Updated info for {current_user_selection}")
                else:
                    st.error("Failed to update user info")
    
    def _render_password_reset_section(self, current_user) -> None:
        """Render admin password reset section."""
        st.markdown("---")
        st.subheader("🔑 Admin Reset User Password")
        
        all_users = self.auth_service.get_all_users()
        other_users = [u for u in all_users.keys() if u != current_user.username]
        
        target_user = st.selectbox("Select a user to reset password:", other_users, key="resetpw_user")
        new_admin_pass = st.text_input("New password for user", type="password", key="resetpw_val")
        
        # Show password validation
        if new_admin_pass:
            from ..services import PasswordService
            if not PasswordService.is_valid_password(new_admin_pass):
                st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        
        if st.button("Reset Password", key="resetpw_btn") and target_user and new_admin_pass:
            if self.auth_service.admin_reset_password(target_user, new_admin_pass, current_user.username):
                st.success(f"Password for user '{target_user}' has been reset.")
            else:
                st.error("Failed to reset password")
    
    def _render_unlock_accounts_section(self, current_user) -> None:
        """Render unlock accounts section."""
        st.markdown("---")
        st.subheader("🔓 Unlock Locked Accounts")
        
        locked_users = self.auth_service.get_locked_users()
        
        if locked_users:
            unlock_user = st.selectbox("Select a user to unlock:", locked_users)
            if st.button("Unlock User"):
                if self.auth_service.unlock_user(unlock_user, current_user.username):
                    st.success(f"{unlock_user} has been unlocked.")
                    st.rerun()
                else:
                    st.error("Failed to unlock user")
        else:
            st.info("No locked users currently.")
    
    def _render_create_user_section(self) -> None:
        """Render create new user section."""
        st.markdown("---")
        st.subheader("➕ Create New User")
        
        new_username = st.text_input("New username", key="newuser_name")
        new_email = st.text_input("New user's email", key="newuser_email")
        new_password = st.text_input("New password", type="password", key="newuser_pw")
        
        # Show password validation
        if new_password:
            from ..services import PasswordService
            if not PasswordService.is_valid_password(new_password):
                st.warning("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        
        selected_role = st.selectbox("Role for new user", ["admin", "viewer"], key="newuser_role")
        
        if st.button("Create User", key="newuser_btn") and new_username and new_password and new_email:
            if self.auth_service.create_user(new_username, new_email, new_password, selected_role):
                st.success(f"User '{new_username}' created with role '{selected_role}'")
            else:
                st.error("Failed to create user. User may already exist or invalid data provided.")