"""
User Workflow Integration Tests

Purpose: Test complete user lifecycle scenarios end-to-end
Scope: Authentication service + repositories working together
Dependencies: Real file I/O with temporary directories

Test Categories:
1. Complete user registration workflow
2. Login and logout cycles
3. Password reset scenarios
4. Account lockout and recovery
5. Admin operations on user accounts
"""

import pytest
from service_layer.services import AuthenticationService
from service_layer.repositories import UserRepository, FailedAttemptsRepository, AuditRepository


class TestCompleteUserWorkflow:
    """Integration tests for complete user lifecycle scenarios."""
    
    def test_user_registration_and_login_workflow(self, auth_service_with_real_repos, real_repositories):
        """
        Test: Complete user registration and login workflow
        
        Given: Clean system with no users
        When: Admin creates user, user logs in successfully
        Then: User can authenticate and access system
        And: All operations are audited
        """
        # Arrange
        auth_service = auth_service_with_real_repos
        user_repo, attempts_repo, audit_repo = real_repositories
        
        # Act - Create user
        create_result = auth_service.create_user(
            "new_user",
            "newuser@example.com",
            "SecurePass123!",
            "viewer"
        )
        
        # Act - Login with new user
        login_result = auth_service.authenticate("new_user", "SecurePass123!")
        
        # Assert - User creation succeeded
        assert create_result == True
        
        # Assert - Login succeeded
        assert login_result.success == True
        assert login_result.user.username == "new_user"
        assert login_result.user.email == "newuser@example.com"
        assert login_result.user.role == "viewer"
        
        # Assert - User exists in repository
        user_data = user_repo.find_by_username("new_user")
        assert user_data is not None
        assert user_data["email"] == "newuser@example.com"
        assert user_data["role"] == "viewer"
        
        # Assert - Audit trail exists
        audit_log = audit_repo.get_log_content()
        assert "User created: new_user (viewer)" in audit_log
        assert "Successful login: new_user" in audit_log
    
    def test_failed_login_attempts_and_lockout_workflow(self, auth_service_with_real_repos, real_repositories):
        """
        Test: Failed login attempts leading to account lockout
        
        Given: Valid user account
        When: Multiple failed login attempts occur
        Then: Account becomes locked after threshold
        And: Subsequent login attempts require CAPTCHA
        And: All attempts are tracked and audited
        """
        # Arrange
        auth_service = auth_service_with_real_repos
        user_repo, attempts_repo, audit_repo = real_repositories
        
        # Create test user
        auth_service.create_user("lockout_user", "test@example.com", "ValidPass123!", "viewer")
        
        # Act - Perform multiple failed login attempts
        failed_results = []
        for i in range(4):  # Exceed lockout threshold
            result = auth_service.authenticate("lockout_user", "wrong_password")
            failed_results.append(result)
        
        # Act - Check if CAPTCHA is required
        captcha_required = auth_service.needs_captcha("lockout_user")
        
        # Act - Attempt login after lockout
        locked_result = auth_service.authenticate("lockout_user", "ValidPass123!")
        
        # Assert - All attempts failed
        for result in failed_results:
            assert result.success == False
        
        # Assert - Account is locked
        assert captcha_required == True
        assert locked_result.success == False
        assert locked_result.requires_captcha == True
        assert "Account locked" in locked_result.error_message
        
        # Assert - Failed attempts are tracked
        attempt_data = attempts_repo.get_attempts("lockout_user")
        assert attempt_data["count"] >= 3
        
        # Assert - Audit log shows all failed attempts
        audit_log = audit_repo.get_log_content()
        assert "Failed login attempt for username: lockout_user" in audit_log
    
    def test_password_reset_workflow(self, auth_service_with_real_repos, real_repositories):
        """
        Test: Password reset and subsequent login workflow
        
        Given: User with known password
        When: Password is reset to new value
        Then: Old password no longer works
        And: New password allows successful login
        And: Password change is audited
        """
        # Arrange
        auth_service = auth_service_with_real_repos
        user_repo, attempts_repo, audit_repo = real_repositories
        
        original_password = "OriginalPass123!"
        new_password = "NewPassword456!"
        
        # Create user with original password
        auth_service.create_user("reset_user", "reset@example.com", original_password, "admin")
        
        # Verify original password works
        original_login = auth_service.authenticate("reset_user", original_password)
        assert original_login.success == True
        
        # Act - Reset password
        reset_result = auth_service.reset_password("reset_user", new_password)
        
        # Act - Try old password (should fail)
        old_password_result = auth_service.authenticate("reset_user", original_password)
        
        # Act - Try new password (should succeed)
        new_password_result = auth_service.authenticate("reset_user", new_password)
        
        # Assert - Password reset succeeded
        assert reset_result == True
        
        # Assert - Old password no longer works
        assert old_password_result.success == False
        
        # Assert - New password works
        assert new_password_result.success == True
        assert new_password_result.user.username == "reset_user"
        
        # Assert - Audit log shows password reset
        audit_log = audit_repo.get_log_content()
        assert "Password reset by user: reset_user" in audit_log
    
    def test_admin_user_management_workflow(self, auth_service_with_real_repos, real_repositories):
        """
        Test: Admin operations on user accounts workflow
        
        Given: Admin user and target user accounts
        When: Admin performs user management operations
        Then: All operations succeed and are properly audited
        And: User data is correctly updated
        """
        # Arrange
        auth_service = auth_service_with_real_repos
        user_repo, attempts_repo, audit_repo = real_repositories
        
        # Create admin user
        auth_service.create_user("admin_user", "admin@example.com", "AdminPass123!", "admin")
        
        # Create target user
        auth_service.create_user("target_user", "target@example.com", "UserPass123!", "viewer")
        
        # Act - Admin updates user role and email
        update_result = auth_service.update_user("target_user", "newemail@example.com", "admin")
        
        # Act - Admin resets user password
        admin_reset_result = auth_service.admin_reset_password(
            "target_user", 
            "NewAdminSetPass123!", 
            "admin_user"
        )
        
        # Act - Verify new password works
        new_password_login = auth_service.authenticate("target_user", "NewAdminSetPass123!")
        
        # Assert - Update operations succeeded
        assert update_result == True
        assert admin_reset_result == True
        
        # Assert - User data was updated
        updated_user_data = user_repo.find_by_username("target_user")
        assert updated_user_data["email"] == "newemail@example.com"
        assert updated_user_data["role"] == "admin"
        
        # Assert - New password works
        assert new_password_login.success == True
        assert new_password_login.user.role == "admin"
        assert new_password_login.user.email == "newemail@example.com"
        
        # Assert - Admin operations are audited
        audit_log = audit_repo.get_log_content()
        assert "Updated user info: target_user, role=admin, email=newemail@example.com" in audit_log
        assert "Admin admin_user reset password for user: target_user" in audit_log
    
    def test_account_unlock_workflow(self, auth_service_with_real_repos, real_repositories):
        """
        Test: Account lockout and admin unlock workflow
        
        Given: User account that becomes locked
        When: Admin unlocks the account
        Then: User can login successfully again
        And: Failed attempts are cleared
        And: Unlock operation is audited
        """
        # Arrange
        auth_service = auth_service_with_real_repos
        user_repo, attempts_repo, audit_repo = real_repositories
        
        # Create users
        auth_service.create_user("admin_user", "admin@example.com", "AdminPass123!", "admin")
        auth_service.create_user("locked_user", "locked@example.com", "UserPass123!", "viewer")
        
        # Lock the account with failed attempts
        for _ in range(4):
            auth_service.authenticate("locked_user", "wrong_password")
        
        # Verify account is locked
        assert auth_service.needs_captcha("locked_user") == True
        
        # Act - Admin unlocks the account
        unlock_result = auth_service.unlock_user("locked_user", "admin_user")
        
        # Act - User tries to login after unlock
        post_unlock_login = auth_service.authenticate("locked_user", "UserPass123!")
        
        # Assert - Unlock succeeded
        assert unlock_result == True
        
        # Assert - User can login successfully
        assert post_unlock_login.success == True
        assert post_unlock_login.user.username == "locked_user"
        
        # Assert - CAPTCHA no longer required
        assert auth_service.needs_captcha("locked_user") == False
        
        # Assert - Failed attempts were cleared
        attempt_data = attempts_repo.get_attempts("locked_user")
        assert attempt_data is None
        
        # Assert - Unlock is audited
        audit_log = audit_repo.get_log_content()
        assert "Admin admin_user unlocked user: locked_user" in audit_log
    
    def test_user_creation_validation_workflow(self, auth_service_with_real_repos):
        """
        Test: User creation with various validation scenarios
        
        Given: AuthenticationService
        When: Attempting to create users with invalid data
        Then: Appropriate validation occurs
        And: Invalid users are not created
        """
        # Arrange
        auth_service = auth_service_with_real_repos
        
        # Act & Assert - Duplicate username
        auth_service.create_user("duplicate_user", "user1@example.com", "ValidPass123!", "viewer")
        duplicate_result = auth_service.create_user("duplicate_user", "user2@example.com", "ValidPass123!", "admin")
        assert duplicate_result == False
        
        # Act & Assert - Invalid password
        weak_password_result = auth_service.create_user("weak_user", "weak@example.com", "weak", "viewer")
        assert weak_password_result == False
        
        # Act & Assert - Invalid email
        invalid_email_result = auth_service.create_user("invalid_email_user", "not_an_email", "ValidPass123!", "viewer")
        assert invalid_email_result == False
        
        # Act & Assert - Valid user creation still works
        valid_result = auth_service.create_user("valid_user", "valid@example.com", "ValidPass123!", "admin")
        assert valid_result == True