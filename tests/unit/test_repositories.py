"""
Repository Unit Tests

Purpose: Test data access layer operations in isolation
Scope: UserRepository, FailedAttemptsRepository, AuditRepository classes
Dependencies: Temporary files (no permanent data modification)

Test Categories:
1. User data CRUD operations
2. Failed attempts tracking
3. Audit logging functionality
4. File path handling
5. Error conditions and edge cases
"""

import pytest
import tempfile
import os
import json
from service_layer.repositories import UserRepository, FailedAttemptsRepository, AuditRepository


class TestUserRepository:
    """Test suite for user data repository operations."""
    
    def test_save_and_find_user_success(self, temp_directory):
        """
        Test: Save user data and retrieve it successfully
        
        Given: Empty repository and user data
        When: User is saved and then retrieved
        Then: Retrieved data matches saved data
        And: User file is created
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        user_data = {
            "password": "hashed_password_123",
            "email": "test@example.com",
            "role": "admin"
        }
        
        # Act
        user_repo.save_user("test_user", user_data)
        retrieved_data = user_repo.find_by_username("test_user")
        
        # Assert
        assert retrieved_data == user_data
        users_file = os.path.join(temp_directory, "users.json")
        assert os.path.exists(users_file)
    
    def test_find_nonexistent_user_returns_none(self, temp_directory):
        """
        Test: Finding non-existent user returns None
        
        Given: Empty repository
        When: Searching for non-existent user
        Then: Returns None
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        
        # Act
        result = user_repo.find_by_username("nonexistent_user")
        
        # Assert
        assert result is None
    
    def test_user_exists_returns_true_for_existing_user(self, temp_directory):
        """
        Test: user_exists returns True for existing users
        
        Given: Repository with saved user
        When: Checking if user exists
        Then: Returns True
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        user_data = {"password": "hash", "email": "test@example.com", "role": "viewer"}
        user_repo.save_user("existing_user", user_data)
        
        # Act
        result = user_repo.user_exists("existing_user")
        
        # Assert
        assert result == True
    
    def test_user_exists_returns_false_for_nonexistent_user(self, temp_directory):
        """
        Test: user_exists returns False for non-existent users
        
        Given: Empty repository
        When: Checking if user exists
        Then: Returns False
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        
        # Act
        result = user_repo.user_exists("nonexistent_user")
        
        # Assert
        assert result == False
    
    def test_get_all_users_returns_complete_data(self, temp_directory):
        """
        Test: get_all_users returns all saved user data
        
        Given: Repository with multiple users
        When: Getting all users
        Then: Returns dictionary with all user data
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        user1_data = {"password": "hash1", "email": "user1@example.com", "role": "admin"}
        user2_data = {"password": "hash2", "email": "user2@example.com", "role": "viewer"}
        
        user_repo.save_user("user1", user1_data)
        user_repo.save_user("user2", user2_data)
        
        # Act
        all_users = user_repo.get_all_users()
        
        # Assert
        assert len(all_users) == 2
        assert all_users["user1"] == user1_data
        assert all_users["user2"] == user2_data
    
    def test_delete_user_removes_user_data(self, temp_directory):
        """
        Test: delete_user removes user from repository
        
        Given: Repository with saved user
        When: Deleting the user
        Then: User no longer exists in repository
        And: delete_user returns True
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        user_data = {"password": "hash", "email": "test@example.com", "role": "viewer"}
        user_repo.save_user("user_to_delete", user_data)
        
        # Act
        delete_result = user_repo.delete_user("user_to_delete")
        
        # Assert
        assert delete_result == True
        assert user_repo.user_exists("user_to_delete") == False
        assert user_repo.find_by_username("user_to_delete") is None
    
    def test_delete_nonexistent_user_returns_false(self, temp_directory):
        """
        Test: Deleting non-existent user returns False
        
        Given: Empty repository
        When: Attempting to delete non-existent user
        Then: Returns False
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        
        # Act
        result = user_repo.delete_user("nonexistent_user")
        
        # Assert
        assert result == False
    
    def test_update_existing_user_data(self, temp_directory):
        """
        Test: Updating existing user overwrites previous data
        
        Given: Repository with saved user
        When: Saving updated data for same user
        Then: New data overwrites old data
        """
        # Arrange
        user_repo = UserRepository(base_path=temp_directory)
        original_data = {"password": "old_hash", "email": "old@example.com", "role": "viewer"}
        updated_data = {"password": "new_hash", "email": "new@example.com", "role": "admin"}
        
        user_repo.save_user("test_user", original_data)
        
        # Act
        user_repo.save_user("test_user", updated_data)
        retrieved_data = user_repo.find_by_username("test_user")
        
        # Assert
        assert retrieved_data == updated_data
        assert retrieved_data != original_data


class TestFailedAttemptsRepository:
    """Test suite for failed login attempts repository."""
    
    def test_save_and_get_attempts_success(self, temp_directory):
        """
        Test: Save failed attempt data and retrieve it
        
        Given: Empty failed attempts repository
        When: Saving attempt data and retrieving it
        Then: Retrieved data matches saved data
        """
        # Arrange
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        attempt_data = {"count": 2, "last_attempt": "2024-01-01T10:00:00"}
        
        # Act
        attempts_repo.save_attempt("test_user", attempt_data)
        retrieved_data = attempts_repo.get_attempts("test_user")
        
        # Assert
        assert retrieved_data == attempt_data
    
    def test_get_attempts_for_nonexistent_user_returns_none(self, temp_directory):
        """
        Test: Getting attempts for non-existent user returns None
        
        Given: Empty attempts repository
        When: Getting attempts for non-existent user
        Then: Returns None
        """
        # Arrange
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        
        # Act
        result = attempts_repo.get_attempts("nonexistent_user")
        
        # Assert
        assert result is None
    
    def test_clear_attempts_removes_user_data(self, temp_directory):
        """
        Test: clear_attempts removes user's failed attempt data
        
        Given: Repository with saved attempt data
        When: Clearing attempts for user
        Then: User's attempt data is removed
        """
        # Arrange
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        attempt_data = {"count": 3, "last_attempt": "2024-01-01T10:00:00"}
        attempts_repo.save_attempt("test_user", attempt_data)
        
        # Act
        attempts_repo.clear_attempts("test_user")
        
        # Assert
        assert attempts_repo.get_attempts("test_user") is None
    
    def test_clear_attempts_for_nonexistent_user_succeeds(self, temp_directory):
        """
        Test: Clearing attempts for non-existent user doesn't error
        
        Given: Empty attempts repository
        When: Clearing attempts for non-existent user
        Then: Operation succeeds without error
        """
        # Arrange
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        
        # Act & Assert (should not raise exception)
        attempts_repo.clear_attempts("nonexistent_user")
    
    def test_get_all_attempts_returns_complete_data(self, temp_directory):
        """
        Test: get_all_attempts returns all failed attempt data
        
        Given: Repository with multiple users' attempt data
        When: Getting all attempts
        Then: Returns dictionary with all attempt data
        """
        # Arrange
        attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
        user1_attempts = {"count": 1, "last_attempt": "2024-01-01T10:00:00"}
        user2_attempts = {"count": 3, "last_attempt": "2024-01-01T11:00:00"}
        
        attempts_repo.save_attempt("user1", user1_attempts)
        attempts_repo.save_attempt("user2", user2_attempts)
        
        # Act
        all_attempts = attempts_repo.get_all_attempts()
        
        # Assert
        assert len(all_attempts) == 2
        assert all_attempts["user1"] == user1_attempts
        assert all_attempts["user2"] == user2_attempts


class TestAuditRepository:
    """Test suite for audit logging repository."""
    
    def test_log_event_creates_audit_entry(self, temp_directory):
        """
        Test: log_event writes audit entry to file
        
        Given: Empty audit repository
        When: Logging an event
        Then: Event is written to audit log file
        And: Log file is created
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        event_message = "User login successful"
        
        # Act
        audit_repo.log_event(event_message)
        
        # Assert
        log_content = audit_repo.get_log_content()
        assert event_message in log_content
        assert audit_repo.log_exists() == True
    
    def test_multiple_log_events_are_appended(self, temp_directory):
        """
        Test: Multiple log events are appended to same file
        
        Given: Audit repository with existing log entry
        When: Logging additional events
        Then: All events appear in log content
        And: Events are in chronological order
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        event1 = "First event"
        event2 = "Second event"
        event3 = "Third event"
        
        # Act
        audit_repo.log_event(event1)
        audit_repo.log_event(event2)
        audit_repo.log_event(event3)
        
        # Assert
        log_content = audit_repo.get_log_content()
        assert event1 in log_content
        assert event2 in log_content
        assert event3 in log_content
        # Verify order (first event should appear before last)
        assert log_content.index(event1) < log_content.index(event3)
    
    def test_get_log_content_empty_file_returns_empty_string(self, temp_directory):
        """
        Test: get_log_content returns empty string for non-existent file
        
        Given: No audit log file exists
        When: Getting log content
        Then: Returns empty string
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        
        # Act
        log_content = audit_repo.get_log_content()
        
        # Assert
        assert log_content == ""
    
    def test_log_exists_returns_false_for_nonexistent_file(self, temp_directory):
        """
        Test: log_exists returns False when no log file exists
        
        Given: No audit log file exists
        When: Checking if log exists
        Then: Returns False
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        
        # Act
        result = audit_repo.log_exists()
        
        # Assert
        assert result == False
    
    def test_log_exists_returns_true_after_logging(self, temp_directory):
        """
        Test: log_exists returns True after logging an event
        
        Given: Empty audit repository
        When: Logging an event and checking existence
        Then: Returns True
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        
        # Act
        audit_repo.log_event("Test event")
        result = audit_repo.log_exists()
        
        # Assert
        assert result == True
    
    def test_log_entries_include_timestamps(self, temp_directory):
        """
        Test: Log entries include timestamp information
        
        Given: Audit repository
        When: Logging an event
        Then: Log entry includes timestamp in brackets
        And: Timestamp format is recognizable
        """
        # Arrange
        audit_repo = AuditRepository(base_path=temp_directory)
        event_message = "Timestamped event"
        
        # Act
        audit_repo.log_event(event_message)
        
        # Assert
        log_content = audit_repo.get_log_content()
        assert "[" in log_content  # Timestamp brackets
        assert "]" in log_content
        assert event_message in log_content
        # Verify timestamp comes before message
        bracket_pos = log_content.index("]")
        message_pos = log_content.index(event_message)
        assert bracket_pos < message_pos