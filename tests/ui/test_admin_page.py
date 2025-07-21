"""
Admin Page UI Tests

Purpose: Test admin panel UI components and interactions
Scope: AdminPage class with mocked services
Dependencies: Mocked services and repositories

Test Categories:
1. Admin panel rendering and access control
2. User management interface
3. Password reset functionality
4. Account unlock operations
5. User creation form
6. Audit log display
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import streamlit as st
from service_layer.pages import AdminPage
from service_layer.models import User


class TestAdminPageAccessControl:
    """Test suite for admin page access control."""
    
    def test_admin_page_renders_for_admin_user(self):
        """
        Test: Admin page renders when user has admin role
        
        Given: User with admin role
        When: Admin page render() is called
        Then: Admin panel sections are displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        admin_user = User("admin_user", "admin@example.com", "admin", "hash")
        
        # Act
        with patch('streamlit.subheader') as mock_subheader:
            admin_page.render(admin_user)
        
        # Assert
        mock_subheader.assert_called_with("🛠 Admin Panel")
    
    def test_admin_page_hidden_for_non_admin_user(self):
        """
        Test: Admin page is hidden for non-admin users
        
        Given: User with viewer role
        When: Admin page render() is called
        Then: No admin panel content is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        viewer_user = User("viewer_user", "viewer@example.com", "viewer", "hash")
        
        # Act
        with patch('streamlit.subheader') as mock_subheader:
            admin_page.render(viewer_user)
        
        # Assert
        mock_subheader.assert_not_called()
    
    def test_admin_page_hidden_for_none_user(self):
        """
        Test: Admin page is hidden when no user is provided
        
        Given: None user (not authenticated)
        When: Admin page render() is called
        Then: No admin panel content is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        # Act
        with patch('streamlit.subheader') as mock_subheader:
            admin_page.render(None)
        
        # Assert
        mock_subheader.assert_not_called()


class TestAuditLogSection:
    """Test suite for audit log display functionality."""
    
    def test_audit_log_displays_when_exists(self):
        """
        Test: Audit log content is displayed when log exists
        
        Given: Audit repository with log content
        When: Audit log section is rendered
        Then: Log content is displayed in text area
        And: Download button is available
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        admin_user = User("admin_user", "admin@example.com", "admin", "hash")
        audit_repo.log_exists.return_value = True
        audit_repo.get_log_content.return_value = "Sample audit log content"
        
        # Act
        with patch('streamlit.text_area') as mock_text_area, \
             patch('streamlit.download_button') as mock_download:
            admin_page._render_audit_log_section()
        
        # Assert
        mock_text_area.assert_called_once_with("Audit Log", "Sample audit log content", height=200)
        mock_download.assert_called_once()
    
    def test_audit_log_shows_info_when_not_exists(self):
        """
        Test: Info message shown when audit log doesn't exist
        
        Given: Audit repository with no log file
        When: Audit log section is rendered
        Then: Info message is displayed
        And: No text area or download button shown
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        audit_repo.log_exists.return_value = False
        
        # Act
        with patch('streamlit.info') as mock_info, \
             patch('streamlit.text_area') as mock_text_area, \
             patch('streamlit.download_button') as mock_download:
            admin_page._render_audit_log_section()
        
        # Assert
        mock_info.assert_called_once_with("No audit log available.")
        mock_text_area.assert_not_called()
        mock_download.assert_not_called()


class TestUserManagementSection:
    """Test suite for user management functionality."""
    
    def test_user_management_displays_existing_users(self):
        """
        Test: User management section displays existing users
        
        Given: Auth service with multiple users
        When: User management section is rendered
        Then: User selection dropdown is displayed
        And: Current user data is pre-filled
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        auth_service.get_all_users.return_value = {
            "user1": {"email": "user1@example.com", "role": "admin"},
            "user2": {"email": "user2@example.com", "role": "viewer"}
        }
        
        # Act
        with patch('streamlit.selectbox', return_value="user1") as mock_selectbox, \
             patch('streamlit.text_input') as mock_text_input, \
             patch('streamlit.button', return_value=False):
            admin_page._render_user_management_section()
        
        # Assert
        mock_selectbox.assert_called_once_with("Select a user to update:", ["user1", "user2"])
    
    def test_user_update_success_shows_message(self):
        """
        Test: Successful user update shows success message
        
        Given: Valid user update data
        When: Update button is clicked
        Then: Auth service update_user is called
        And: Success message is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        auth_service.get_all_users.return_value = {
            "test_user": {"email": "old@example.com", "role": "viewer"}
        }
        auth_service.update_user.return_value = True
        
        # Act
        with patch('streamlit.selectbox', return_value="test_user"), \
             patch('streamlit.text_input', side_effect=["new@example.com"]), \
             patch('streamlit.selectbox', return_value="admin"), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.success') as mock_success:
            admin_page._render_user_management_section()
        
        # Assert
        auth_service.update_user.assert_called_once_with("test_user", "new@example.com", "admin")
        mock_success.assert_called_once_with("Updated info for test_user")
    
    def test_user_update_failure_shows_error(self):
        """
        Test: Failed user update shows error message
        
        Given: User update that fails
        When: Update button is clicked
        Then: Error message is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        auth_service.get_all_users.return_value = {
            "test_user": {"email": "test@example.com", "role": "viewer"}
        }
        auth_service.update_user.return_value = False
        
        # Act
        with patch('streamlit.selectbox', return_value="test_user"), \
             patch('streamlit.text_input', side_effect=["new@example.com"]), \
             patch('streamlit.selectbox', return_value="admin"), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.error') as mock_error:
            admin_page._render_user_management_section()
        
        # Assert
        mock_error.assert_called_once_with("Failed to update user info")


class TestPasswordResetSection:
    """Test suite for admin password reset functionality."""
    
    def test_password_reset_excludes_current_user(self):
        """
        Test: Password reset dropdown excludes current admin user
        
        Given: Multiple users including current admin
        When: Password reset section is rendered
        Then: Current user is excluded from target user dropdown
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        current_user = User("admin_user", "admin@example.com", "admin", "hash")
        auth_service.get_all_users.return_value = {
            "admin_user": {"email": "admin@example.com", "role": "admin"},
            "other_user": {"email": "other@example.com", "role": "viewer"}
        }
        
        # Act
        with patch('streamlit.selectbox', return_value="other_user") as mock_selectbox, \
             patch('streamlit.text_input'), \
             patch('streamlit.button', return_value=False):
            admin_page._render_password_reset_section(current_user)
        
        # Assert
        mock_selectbox.assert_called_once_with("Select a user to reset password:", ["other_user"], key="resetpw_user")
    
    def test_password_reset_shows_validation_warning(self):
        """
        Test: Password reset shows validation warning for weak passwords
        
        Given: Weak password input
        When: Password is entered
        Then: Validation warning is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        current_user = User("admin_user", "admin@example.com", "admin", "hash")
        auth_service.get_all_users.return_value = {
            "admin_user": {"email": "admin@example.com", "role": "admin"},
            "target_user": {"email": "target@example.com", "role": "viewer"}
        }
        
        # Act
        with patch('streamlit.selectbox', return_value="target_user"), \
             patch('streamlit.text_input', return_value="weak"), \
             patch('streamlit.button', return_value=False), \
             patch('streamlit.warning') as mock_warning, \
             patch('service_layer.pages.admin_page.PasswordService') as mock_password_service:
            
            mock_password_service.is_valid_password.return_value = False
            admin_page._render_password_reset_section(current_user)
        
        # Assert
        mock_warning.assert_called_once()
    
    def test_successful_password_reset_shows_success(self):
        """
        Test: Successful password reset shows success message
        
        Given: Valid target user and strong password
        When: Reset password button is clicked
        Then: Success message is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        current_user = User("admin_user", "admin@example.com", "admin", "hash")
        auth_service.get_all_users.return_value = {
            "admin_user": {"email": "admin@example.com", "role": "admin"},
            "target_user": {"email": "target@example.com", "role": "viewer"}
        }
        auth_service.admin_reset_password.return_value = True
        
        # Act
        with patch('streamlit.selectbox', return_value="target_user"), \
             patch('streamlit.text_input', return_value="StrongPass123!"), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.success') as mock_success, \
             patch('service_layer.pages.admin_page.PasswordService') as mock_password_service:
            
            mock_password_service.is_valid_password.return_value = True
            admin_page._render_password_reset_section(current_user)
        
        # Assert
        auth_service.admin_reset_password.assert_called_once_with("target_user", "StrongPass123!", "admin_user")
        mock_success.assert_called_once_with("Password for user 'target_user' has been reset.")


class TestAccountUnlockSection:
    """Test suite for account unlock functionality."""
    
    def test_unlock_section_shows_locked_users(self):
        """
        Test: Unlock section displays list of locked users
        
        Given: Auth service with locked user accounts
        When: Unlock section is rendered
        Then: Locked users are displayed in dropdown
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        current_user = User("admin_user", "admin@example.com", "admin", "hash")
        auth_service.get_locked_users.return_value = ["locked_user1", "locked_user2"]
        
        # Act
        with patch('streamlit.selectbox', return_value="locked_user1") as mock_selectbox, \
             patch('streamlit.button', return_value=False):
            admin_page._render_unlock_accounts_section(current_user)
        
        # Assert
        mock_selectbox.assert_called_once_with("Select a user to unlock:", ["locked_user1", "locked_user2"])
    
    def test_unlock_section_shows_info_when_no_locked_users(self):
        """
        Test: Info message shown when no users are locked
        
        Given: No locked user accounts
        When: Unlock section is rendered
        Then: Info message is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        current_user = User("admin_user", "admin@example.com", "admin", "hash")
        auth_service.get_locked_users.return_value = []
        
        # Act
        with patch('streamlit.info') as mock_info:
            admin_page._render_unlock_accounts_section(current_user)
        
        # Assert
        mock_info.assert_called_once_with("No locked users currently.")
    
    def test_successful_unlock_shows_success_and_reruns(self):
        """
        Test: Successful unlock shows success message and reruns page
        
        Given: Locked user account
        When: Unlock button is clicked
        Then: Success message is displayed
        And: Page is rerun to refresh state
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        current_user = User("admin_user", "admin@example.com", "admin", "hash")
        auth_service.get_locked_users.return_value = ["locked_user"]
        auth_service.unlock_user.return_value = True
        
        # Act
        with patch('streamlit.selectbox', return_value="locked_user"), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.success') as mock_success, \
             patch('streamlit.rerun') as mock_rerun:
            admin_page._render_unlock_accounts_section(current_user)
        
        # Assert
        auth_service.unlock_user.assert_called_once_with("locked_user", "admin_user")
        mock_success.assert_called_once_with("locked_user has been unlocked.")
        mock_rerun.assert_called_once()


class TestUserCreationSection:
    """Test suite for new user creation functionality."""
    
    def test_user_creation_form_renders_all_fields(self):
        """
        Test: User creation form renders all required input fields
        
        Given: Admin page user creation section
        When: Section is rendered
        Then: All input fields are displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        # Act
        with patch('streamlit.text_input') as mock_text_input, \
             patch('streamlit.selectbox') as mock_selectbox, \
             patch('streamlit.button', return_value=False):
            admin_page._render_create_user_section()
        
        # Assert
        # Verify all input fields are created
        expected_calls = [
            (("New username",), {"key": "newuser_name"}),
            (("New user's email",), {"key": "newuser_email"}),
            (("New password",), {"type": "password", "key": "newuser_pw"})
        ]
        mock_text_input.assert_has_calls([patch.call(*args, **kwargs) for args, kwargs in expected_calls])
        mock_selectbox.assert_called_with("Role for new user", ["admin", "viewer"], key="newuser_role")
    
    def test_successful_user_creation_shows_success(self):
        """
        Test: Successful user creation shows success message
        
        Given: Valid new user data
        When: Create user button is clicked
        Then: Success message is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        auth_service.create_user.return_value = True
        
        # Act
        with patch('streamlit.text_input', side_effect=["new_user", "new@example.com", "StrongPass123!"]), \
             patch('streamlit.selectbox', return_value="viewer"), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.success') as mock_success, \
             patch('service_layer.pages.admin_page.PasswordService') as mock_password_service:
            
            mock_password_service.is_valid_password.return_value = True
            admin_page._render_create_user_section()
        
        # Assert
        auth_service.create_user.assert_called_once_with("new_user", "new@example.com", "StrongPass123!", "viewer")
        mock_success.assert_called_once_with("User 'new_user' created with role 'viewer'")
    
    def test_failed_user_creation_shows_error(self):
        """
        Test: Failed user creation shows error message
        
        Given: User creation that fails (duplicate username, etc.)
        When: Create user button is clicked
        Then: Error message is displayed
        """
        # Arrange
        auth_service = Mock()
        audit_repo = Mock()
        admin_page = AdminPage(auth_service, audit_repo)
        
        auth_service.create_user.return_value = False
        
        # Act
        with patch('streamlit.text_input', side_effect=["existing_user", "new@example.com", "StrongPass123!"]), \
             patch('streamlit.selectbox', return_value="viewer"), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.error') as mock_error, \
             patch('service_layer.pages.admin_page.PasswordService') as mock_password_service:
            
            mock_password_service.is_valid_password.return_value = True
            admin_page._render_create_user_section()
        
        # Assert
        mock_error.assert_called_once_with("Failed to create user. User may already exist or invalid data provided.")