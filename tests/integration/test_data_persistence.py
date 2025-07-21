"""
Data Persistence Integration Tests

Purpose: Test file operations and data consistency across components
Scope: Repository file operations + service interactions
Dependencies: Real file I/O with temporary storage

Test Categories:
1. File creation and structure validation
2. Data format consistency
3. Error recovery and data integrity
4. Cross-component data sharing
"""

import pytest
import json
import os
from service_layer.repositories import UserRepository, FailedAttemptsRepository, AuditRepository
from service_layer.services import AuthenticationService


class TestDataPersistence:
    """Integration tests for data persistence and file operations."""
    
    def test_user_data_file_structure_and_format(self, temp_directory):
        """
        Test: User data is persisted in correct JSON format
        
        Given: UserRepository with user data
        When: Users are saved to file
        Then: File contains valid JSON with correct structure
        And: Data can be read by external JSON parser
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        
        # Act - Save multiple users
        user_repo.save_user("user1", {
            "password": "hash1",
            "email": "user1@example.com",
            "role": "admin"
        })
        user_repo.save_user("user2", {
            "password": "hash2", 
            "email": "user2@example.com",
            "role": "viewer"
        })
        
        # Assert - File exists and contains valid JSON
        users_file = os.path.join(temp_directory, "users.json")
        assert os.path.exists(users_file)
        
        # Read file directly and validate JSON structure
        with open(users_file, 'r') as f:
            users_data = json.load(f)
        
        assert isinstance(users_data, dict)
        assert len(users_data) == 2
        assert "user1" in users_data
        assert "user2" in users_data
        
        # Validate user1 structure
        user1_data = users_data["user1"]
        assert user1_data["password"] == "hash1"
        assert user1_data["email"] == "user1@example.com"
        assert user1_data["role"] == "admin"
        
        # Validate user2 structure
        user2_data = users_data["user2"]
        assert user2_data["password"] == "hash2"
        assert user2_data["email"] == "user2@example.com"
        assert user2_data["role"] == "viewer"
    
    def test_failed_attempts_data_persistence(self, temp_directory):
        """
        Test: Failed attempts data is correctly persisted and retrieved
        
        Given: FailedAttemptsRepository
        When: Failed attempt data is saved
        Then: Data persists correctly in JSON format
        And: Timestamps and counts are preserved
        """
        # Arrange
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        
        # Act - Save failed attempts for multiple users
        attempts_repo.save_attempt("user1", {
            "count": 2,
            "last_attempt": "2024-01-01T10:00:00"
        })
        attempts_repo.save_attempt("user2", {
            "count": 1,
            "last_attempt": "2024-01-01T11:00:00"
        })
        
        # Assert - File exists with correct content
        attempts_file = os.path.join(temp_directory, "failed_attempts.json")
        assert os.path.exists(attempts_file)
        
        # Validate file content directly
        with open(attempts_file, 'r') as f:
            attempts_data = json.load(f)
        
        assert len(attempts_data) == 2
        assert attempts_data["user1"]["count"] == 2
        assert attempts_data["user1"]["last_attempt"] == "2024-01-01T10:00:00"
        assert attempts_data["user2"]["count"] == 1
        assert attempts_data["user2"]["last_attempt"] == "2024-01-01T11:00:00"
    
    def test_audit_log_file_format_and_readability(self, temp_directory):
        """
        Test: Audit log maintains readable text format
        
        Given: AuditRepository
        When: Multiple events are logged
        Then: Log file contains human-readable text
        And: Each entry has timestamp and message
        And: Entries are in chronological order
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        
        # Act - Log multiple events
        audit_repo.log_event("User login event")
        audit_repo.log_event("Password change event")
        audit_repo.log_event("Admin action performed")
        
        # Assert - File exists and is readable
        audit_file = os.path.join(temp_directory, "audit.log")
        assert os.path.exists(audit_file)
        
        # Read file directly and validate format
        with open(audit_file, 'r') as f:
            log_content = f.read()
        
        # Validate log structure
        log_lines = log_content.strip().split('\n')
        assert len(log_lines) == 3
        
        # Each line should have timestamp in brackets followed by message
        for line in log_lines:
            assert line.startswith('[')
            assert '] ' in line
            
        # Validate specific messages are present
        assert "User login event" in log_content
        assert "Password change event" in log_content
        assert "Admin action performed" in log_content
    
    def test_cross_repository_data_sharing(self, temp_directory):
        """
        Test: Multiple repositories can access same data files correctly
        
        Given: Multiple repository instances for same data files
        When: Data is written by one and read by another
        Then: Data is consistent across all repository instances
        """
        # Arrange - Multiple repository instances
        user_repo1 = UserRepository(base_path=temp_directory)
        user_repo2 = UserRepository(base_path=temp_directory)
        
        attempts_repo1 = FailedAttemptsRepository(base_path=temp_directory)
        attempts_repo2 = FailedAttemptsRepository(base_path=temp_directory)
        
        # Act - Write data with first instances
        user_repo1.save_user("shared_user", {
            "password": "shared_hash",
            "email": "shared@example.com",
            "role": "admin"
        })
        
        attempts_repo1.save_attempt("shared_user", {
            "count": 3,
            "last_attempt": "2024-01-01T12:00:00"
        })
        
        # Act - Read data with second instances
        user_data = user_repo2.find_by_username("shared_user")
        attempt_data = attempts_repo2.get_attempts("shared_user")
        
        # Assert - Data is consistent across instances
        assert user_data["password"] == "shared_hash"
        assert user_data["email"] == "shared@example.com"
        assert user_data["role"] == "admin"
        
        assert attempt_data["count"] == 3
        assert attempt_data["last_attempt"] == "2024-01-01T12:00:00"
    
    def test_service_integration_with_data_persistence(self, temp_directory):
        """
        Test: Services properly integrate with persistent repositories
        
        Given: AuthenticationService with real repositories
        When: Service operations are performed
        Then: All data changes are persisted correctly
        And: Service state can be reconstructed from files
        """
        # Arrange - Service with real repositories
        user_repo = UserRepository(base_path=temp_directory)
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo = AuditRepository(base_path=temp_directory)
        auth_service = AuthenticationService(user_repo, attempts_repo, audit_repo)
        
        # Act - Perform service operations
        create_result = auth_service.create_user(
            "service_user", 
            "service@example.com", 
            "ServicePass123!", 
            "viewer"
        )
        login_result = auth_service.authenticate("service_user", "ServicePass123!")
        fail_result = auth_service.authenticate("service_user", "wrong_password")
        
        # Create new service instance with fresh repositories (same files)
        user_repo2 = UserRepository(base_path=temp_directory)
        attempts_repo2 = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo2 = AuditRepository(base_path=temp_directory)
        auth_service2 = AuthenticationService(user_repo2, attempts_repo2, audit_repo2)
        
        # Act - Verify service state from persisted data
        login_result2 = auth_service2.authenticate("service_user", "ServicePass123!")
        
        # Assert - Operations succeeded
        assert create_result == True
        assert login_result.success == True
        assert fail_result.success == False
        
        # Assert - New service instance has same state
        assert login_result2.success == True
        assert login_result2.user.username == "service_user"
        assert login_result2.user.email == "service@example.com"
        assert login_result2.user.role == "viewer"
        
        # Assert - Failed attempts are tracked across instances
        attempt_data = attempts_repo2.get_attempts("service_user")
        assert attempt_data["count"] == 1
        
        # Assert - Audit log contains all operations
        audit_content = audit_repo2.get_log_content()
        assert "User created: service_user (viewer)" in audit_content
        assert "Successful login: service_user" in audit_content
        assert "Failed login attempt for username: service_user" in audit_content
    
    def test_file_permissions_and_accessibility(self, temp_directory):
        """
        Test: Created files have appropriate permissions and are accessible
        
        Given: Repositories creating data files
        When: Files are created and written
        Then: Files are readable and writable
        And: File permissions allow proper access
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        audit_repo = AuditRepository(base_path=temp_directory)
        
        # Act - Create files through repository operations
        user_repo.save_user("permission_user", {"password": "hash", "email": "test@example.com", "role": "viewer"})
        attempts_repo.save_attempt("permission_user", {"count": 1, "last_attempt": "2024-01-01T10:00:00"})
        audit_repo.log_event("Permission test event")
        
        # Assert - Files exist and are accessible
        users_file = os.path.join(temp_directory, "users.json")
        attempts_file = os.path.join(temp_directory, "failed_attempts.json")
        audit_file = os.path.join(temp_directory, "audit.log")
        
        assert os.path.exists(users_file)
        assert os.path.exists(attempts_file)
        assert os.path.exists(audit_file)
        
        # Assert - Files are readable
        assert os.access(users_file, os.R_OK)
        assert os.access(attempts_file, os.R_OK)
        assert os.access(audit_file, os.R_OK)
        
        # Assert - Files are writable
        assert os.access(users_file, os.W_OK)
        assert os.access(attempts_file, os.W_OK)
        assert os.access(audit_file, os.W_OK)
        
        # Assert - Files have reasonable sizes
        assert os.path.getsize(users_file) > 0
        assert os.path.getsize(attempts_file) > 0
        assert os.path.getsize(audit_file) > 0
    
    def test_data_integrity_after_partial_operations(self, temp_directory):
        """
        Test: Data integrity is maintained even with interrupted operations
        
        Given: Repository with existing data
        When: Operations are performed that might be interrupted
        Then: Existing data remains intact
        And: New valid data is properly saved
        """
        # Arrange - Create initial data
        user_repo = UserRepository(base_path=temp_directory)
        user_repo.save_user("existing_user", {
            "password": "existing_hash",
            "email": "existing@example.com", 
            "role": "admin"
        })
        
        # Act - Perform additional operations
        user_repo.save_user("new_user", {
            "password": "new_hash",
            "email": "new@example.com",
            "role": "viewer"
        })
        
        # Update existing user
        user_repo.save_user("existing_user", {
            "password": "updated_hash",
            "email": "updated@example.com",
            "role": "viewer"
        })
        
        # Assert - All data is present and correct
        all_users = user_repo.get_all_users()
        assert len(all_users) == 2
        
        # Verify existing user was updated
        existing_user = user_repo.find_by_username("existing_user")
        assert existing_user["password"] == "updated_hash"
        assert existing_user["email"] == "updated@example.com"
        assert existing_user["role"] == "viewer"
        
        # Verify new user was added
        new_user = user_repo.find_by_username("new_user")
        assert new_user["password"] == "new_hash"
        assert new_user["email"] == "new@example.com"
        assert new_user["role"] == "viewer"
        
        # Verify file integrity by reading directly
        users_file = os.path.join(temp_directory, "users.json")
        with open(users_file, 'r') as f:
            file_data = json.load(f)
        
        assert len(file_data) == 2
        assert "existing_user" in file_data
        assert "new_user" in file_data