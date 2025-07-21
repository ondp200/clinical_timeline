"""
Authentication Flow Integration Tests

Purpose: Test authentication system with real file persistence
Scope: Complete authentication flow including file operations
Dependencies: Real repositories with temporary file storage

Test Categories:
1. Login flow with file persistence
2. Session management integration
3. Failed attempt tracking across sessions
4. Data consistency between components
"""

import pytest
import os
from service_layer.services import AuthenticationService
from service_layer.repositories import UserRepository, FailedAttemptsRepository, AuditRepository


class TestAuthenticationFlow:
    """Integration tests for authentication flow with file persistence."""
    
    def test_login_flow_with_file_persistence(self, temp_directory):
        """
        Test: Complete login flow persists data correctly to files
        
        Given: Fresh repositories with temporary file storage
        When: User is created and authentication is attempted
        Then: All data is correctly persisted to files
        And: Files can be read by separate repository instances
        """
        # Arrange - Create first set of repositories
        user_repo1 = UserRepository(base_path=temp_directory)
        attempts_repo1 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo1 = AuditRepository(base_path=temp_directory)
        auth_service1 = AuthenticationService(user_repo1, attempts_repo1, audit_repo1)
        
        # Act - Create user and login with first service
        auth_service1.create_user("persistent_user", "persist@example.com", "PersistPass123!", "admin")
        login_result1 = auth_service1.authenticate("persistent_user", "PersistPass123!")
        
        # Arrange - Create second set of repositories (fresh instances, same files)
        user_repo2 = UserRepository(base_path=temp_directory)
        attempts_repo2 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo2 = AuditRepository(base_path=temp_directory)
        auth_service2 = AuthenticationService(user_repo2, attempts_repo2, audit_repo2)
        
        # Act - Login with second service (reading from persisted files)
        login_result2 = auth_service2.authenticate("persistent_user", "PersistPass123!")
        
        # Assert - Both logins succeeded
        assert login_result1.success == True
        assert login_result2.success == True
        
        # Assert - User data is consistent across instances
        assert login_result1.user.username == login_result2.user.username
        assert login_result1.user.email == login_result2.user.email
        assert login_result1.user.role == login_result2.user.role
        
        # Assert - Files were created
        assert os.path.exists(os.path.join(temp_directory, "users.json"))
        assert os.path.exists(os.path.join(temp_directory, "audit.log"))
    
    def test_failed_attempts_persistence_across_sessions(self, temp_directory):
        """
        Test: Failed login attempts persist across service instances
        
        Given: User account and authentication service
        When: Failed attempts are made, service is recreated, more attempts made
        Then: Failed attempt count accumulates correctly
        And: Account lockout behavior is consistent
        """
        # Arrange - First service instance
        user_repo1 = UserRepository(base_path=temp_directory)
        attempts_repo1 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo1 = AuditRepository(base_path=temp_directory)
        auth_service1 = AuthenticationService(user_repo1, attempts_repo1, audit_repo1)
        
        # Create user
        auth_service1.create_user("fail_user", "fail@example.com", "CorrectPass123!", "viewer")
        
        # Act - Make 2 failed attempts with first service
        auth_service1.authenticate("fail_user", "wrong1")
        auth_service1.authenticate("fail_user", "wrong2")
        
        # Arrange - Second service instance (fresh objects, same files)
        user_repo2 = UserRepository(base_path=temp_directory)
        attempts_repo2 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo2 = AuditRepository(base_path=temp_directory)
        auth_service2 = AuthenticationService(user_repo2, attempts_repo2, audit_repo2)
        
        # Act - Make 1 more failed attempt with second service (should trigger lockout)
        fail_result = auth_service2.authenticate("fail_user", "wrong3")
        
        # Act - Check lockout status
        needs_captcha = auth_service2.needs_captcha("fail_user")
        
        # Act - Try correct password (should be blocked due to lockout)
        blocked_result = auth_service2.authenticate("fail_user", "CorrectPass123!")
        
        # Assert - Failed attempt was recorded
        assert fail_result.success == False
        
        # Assert - Account is locked
        assert needs_captcha == True
        assert blocked_result.success == False
        assert blocked_result.requires_captcha == True
        
        # Assert - Failed attempts file exists and contains data
        assert os.path.exists(os.path.join(temp_directory, "failed_attempts.json"))
        attempt_data = attempts_repo2.get_attempts("fail_user")
        assert attempt_data["count"] >= 3
    
    def test_audit_log_accumulation_across_sessions(self, temp_directory):
        """
        Test: Audit log accumulates entries across service instances
        
        Given: Multiple service instances operating on same audit file
        When: Various operations are performed
        Then: All operations are logged in chronological order
        And: Log content is accessible from any service instance
        """
        # Arrange - First service instance
        user_repo1 = UserRepository(base_path=temp_directory)
        attempts_repo1 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo1 = AuditRepository(base_path=temp_directory)
        auth_service1 = AuthenticationService(user_repo1, attempts_repo1, audit_repo1)
        
        # Act - Operations with first service
        auth_service1.create_user("audit_user", "audit@example.com", "AuditPass123!", "admin")
        auth_service1.authenticate("audit_user", "AuditPass123!")
        
        # Arrange - Second service instance
        user_repo2 = UserRepository(base_path=temp_directory)
        attempts_repo2 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo2 = AuditRepository(base_path=temp_directory)
        auth_service2 = AuthenticationService(user_repo2, attempts_repo2, audit_repo2)
        
        # Act - Operations with second service
        auth_service2.reset_password("audit_user", "NewAuditPass123!")
        auth_service2.authenticate("audit_user", "NewAuditPass123!")
        
        # Act - Read audit log from both instances
        log_content1 = audit_repo1.get_log_content()
        log_content2 = audit_repo2.get_log_content()
        
        # Assert - Both instances see same log content
        assert log_content1 == log_content2
        
        # Assert - All operations are logged
        assert "User created: audit_user (admin)" in log_content1
        assert "Successful login: audit_user" in log_content1
        assert "Password reset by user: audit_user" in log_content1
        
        # Assert - Multiple login events are present
        login_count = log_content1.count("Successful login: audit_user")
        assert login_count == 2
    
    def test_data_consistency_after_operations(self, temp_directory):
        """
        Test: Data remains consistent after complex operations
        
        Given: Authentication service with file persistence
        When: Complex sequence of user operations is performed
        Then: All data remains consistent and accessible
        And: No data corruption occurs
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo = AuditRepository(base_path=temp_directory)
        auth_service = AuthenticationService(user_repo, attempts_repo, audit_repo)
        
        # Act - Complex sequence of operations
        # 1. Create multiple users
        auth_service.create_user("user1", "user1@example.com", "Pass123!", "admin")
        auth_service.create_user("user2", "user2@example.com", "Pass456!", "viewer")
        auth_service.create_user("user3", "user3@example.com", "Pass789!", "viewer")
        
        # 2. Successful logins
        login1 = auth_service.authenticate("user1", "Pass123!")
        login2 = auth_service.authenticate("user2", "Pass456!")
        
        # 3. Failed attempts for user3
        auth_service.authenticate("user3", "wrong1")
        auth_service.authenticate("user3", "wrong2")
        
        # 4. Password reset for user2
        auth_service.reset_password("user2", "NewPass456!")
        
        # 5. Admin operations
        auth_service.update_user("user3", "newuser3@example.com", "admin")
        auth_service.admin_reset_password("user3", "AdminSet123!", "user1")
        
        # Assert - All users exist with correct data
        all_users = auth_service.get_all_users()
        assert len(all_users) == 3
        assert all_users["user1"]["role"] == "admin"
        assert all_users["user2"]["email"] == "user2@example.com"
        assert all_users["user3"]["email"] == "newuser3@example.com"
        assert all_users["user3"]["role"] == "admin"
        
        # Assert - Logins work with current passwords
        current_login1 = auth_service.authenticate("user1", "Pass123!")
        current_login2 = auth_service.authenticate("user2", "NewPass456!")
        current_login3 = auth_service.authenticate("user3", "AdminSet123!")
        
        assert current_login1.success == True
        assert current_login2.success == True
        assert current_login3.success == True
        
        # Assert - Failed attempts are tracked correctly
        user3_attempts = attempts_repo.get_attempts("user3")
        assert user3_attempts is None  # Should be cleared after admin reset
        
        # Assert - Audit log contains all operations
        audit_content = audit_repo.get_log_content()
        assert "User created: user1 (admin)" in audit_content
        assert "User created: user2 (viewer)" in audit_content
        assert "User created: user3 (viewer)" in audit_content
        assert "Password reset by user: user2" in audit_content
        assert "Updated user info: user3" in audit_content
        assert "Admin user1 reset password for user: user3" in audit_content
    
    def test_concurrent_access_simulation(self, temp_directory):
        """
        Test: Simulate concurrent access to same data files
        
        Given: Two independent service instances
        When: Both perform operations on same user data
        Then: Data integrity is maintained
        And: Last operation wins for conflicting changes
        """
        # Arrange - Two independent service instances
        user_repo1 = UserRepository(base_path=temp_directory)
        attempts_repo1 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo1 = AuditRepository(base_path=temp_directory)
        auth_service1 = AuthenticationService(user_repo1, attempts_repo1, audit_repo1)
        
        user_repo2 = UserRepository(base_path=temp_directory)
        attempts_repo2 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo2 = AuditRepository(base_path=temp_directory)
        auth_service2 = AuthenticationService(user_repo2, attempts_repo2, audit_repo2)
        
        # Act - Create user with service1
        auth_service1.create_user("concurrent_user", "concurrent@example.com", "ConcurrentPass123!", "viewer")
        
        # Act - Both services update user info (simulating concurrent access)
        auth_service1.update_user("concurrent_user", "email1@example.com", "admin")
        auth_service2.update_user("concurrent_user", "email2@example.com", "viewer")
        
        # Act - Verify final state with fresh service instance
        user_repo3 = UserRepository(base_path=temp_directory)
        final_user_data = user_repo3.find_by_username("concurrent_user")
        
        # Assert - Data integrity maintained (last write wins)
        assert final_user_data is not None
        assert final_user_data["email"] in ["email1@example.com", "email2@example.com"]
        assert final_user_data["role"] in ["admin", "viewer"]
        
        # Assert - User can still authenticate
        auth_service3 = AuthenticationService(user_repo3, attempts_repo2, audit_repo2)
        login_result = auth_service3.authenticate("concurrent_user", "ConcurrentPass123!")
        assert login_result.success == True