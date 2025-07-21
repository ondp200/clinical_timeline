"""
Authentication Service Unit Tests

Purpose: Test authentication business logic in isolation
Scope: AuthenticationService and PasswordService classes
Dependencies: Mocked repositories (no real file I/O)

Test Categories:
1. Successful authentication scenarios
2. Failed authentication handling  
3. Account lockout mechanisms
4. Password validation rules
5. User management operations
"""

import pytest
from unittest.mock import Mock, patch
from service_layer.services import AuthenticationService, PasswordService
from service_layer.models import AuthenticationResult, User


class TestAuthenticationService:
    """Test suite for AuthenticationService business logic."""
    
    def test_successful_authentication_returns_user_object(self, auth_service_with_mocks, mock_repositories):
        """
        Test: Successful authentication with valid credentials
        
        Given: Valid username and password in repository
        When: authenticate() is called
        Then: Returns success=True with User object
        And: Audit log records successful login
        And: Failed attempts are cleared
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        user_repo.find_by_username.return_value = {
            "password": "$2b$12$hashed_password",
            "email": "test@example.com", 
            "role": "admin"
        }
        attempts_repo.get_attempts.return_value = None  # No failed attempts
        
        # Act
        with patch.object(PasswordService, 'verify_password', return_value=True):
            result = auth_service.authenticate("test_user", "correct_password")
        
        # Assert
        assert result.success == True
        assert result.user.username == "test_user"
        assert result.user.role == "admin"
        assert result.user.email == "test@example.com"
        audit_repo.log_event.assert_called_with("Successful login: test_user")
        attempts_repo.clear_attempts.assert_called_with("test_user")
    
    def test_invalid_password_returns_failure(self, auth_service_with_mocks, mock_repositories):
        """
        Test: Authentication fails with incorrect password
        
        Given: Valid username but incorrect password  
        When: authenticate() is called
        Then: Returns success=False with error message
        And: Failed attempt is recorded
        And: Audit log records failed attempt
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        user_repo.find_by_username.return_value = {
            "password": "$2b$12$hashed_password",
            "email": "test@example.com",
            "role": "admin"
        }
        attempts_repo.get_attempts.return_value = None
        
        # Act
        with patch.object(PasswordService, 'verify_password', return_value=False):
            result = auth_service.authenticate("test_user", "wrong_password")
        
        # Assert
        assert result.success == False
        assert "Invalid username or password" in result.error_message
        audit_repo.log_event.assert_called_with("Failed login attempt for username: test_user")
        # Verify failed attempt was recorded
        attempts_repo.save_attempt.assert_called_once()
    
    def test_nonexistent_user_returns_failure(self, auth_service_with_mocks, mock_repositories):
        """
        Test: Authentication fails for non-existent user
        
        Given: Username not in repository
        When: authenticate() is called
        Then: Returns success=False with error message
        And: Failed attempt is recorded
        And: Audit log records failed attempt with non-existent user
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        user_repo.find_by_username.return_value = None  # User doesn't exist
        attempts_repo.get_attempts.return_value = None
        
        # Act
        result = auth_service.authenticate("nonexistent_user", "any_password")
        
        # Assert
        assert result.success == False
        assert "Invalid username or password" in result.error_message
        audit_repo.log_event.assert_called_with("Failed login attempt for non-existent username: nonexistent_user")
        attempts_repo.save_attempt.assert_called_once()
    
    def test_account_lockout_after_failed_attempts(self, auth_service_with_mocks, mock_repositories):
        """
        Test: Account lockout after multiple failed attempts
        
        Given: User account with 3+ failed attempts
        When: authenticate() is called
        Then: Returns success=False with account locked message
        And: requires_captcha=True
        And: No password verification attempted
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        # Mock account with 3 failed attempts (locked)
        attempts_repo.get_attempts.return_value = {"count": 3}
        
        # Act
        result = auth_service.authenticate("locked_user", "any_password")
        
        # Assert
        assert result.success == False
        assert result.requires_captcha == True
        assert "Account locked" in result.error_message
        # Verify password verification was not attempted
        user_repo.find_by_username.assert_not_called()
    
    def test_create_user_success(self, auth_service_with_mocks, mock_repositories):
        """
        Test: Successful user creation
        
        Given: Valid user data and username doesn't exist
        When: create_user() is called
        Then: Returns True
        And: User is saved to repository
        And: Audit log records user creation
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        user_repo.user_exists.return_value = False
        
        # Act
        with patch.object(PasswordService, 'is_valid_password', return_value=True), \
             patch.object(PasswordService, 'hash_password', return_value="hashed_password"):
            result = auth_service.create_user(
                "new_user", 
                "test@example.com", 
                "ValidPassword123!", 
                "viewer"
            )
        
        # Assert
        assert result == True
        user_repo.save_user.assert_called_once()
        audit_repo.log_event.assert_called_with("User created: new_user (viewer)")
    
    def test_create_user_fails_with_existing_username(self, auth_service_with_mocks, mock_repositories):
        """
        Test: User creation fails when username already exists
        
        Given: Username already exists in repository
        When: create_user() is called
        Then: Returns False
        And: No user data is saved
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        user_repo.user_exists.return_value = True  # User already exists
        
        # Act
        result = auth_service.create_user(
            "existing_user", 
            "test@example.com", 
            "ValidPassword123!", 
            "viewer"
        )
        
        # Assert
        assert result == False
        user_repo.save_user.assert_not_called()
    
    def test_reset_password_success(self, auth_service_with_mocks, mock_repositories):
        """
        Test: Successful password reset
        
        Given: Valid username and new password
        When: reset_password() is called
        Then: Returns True
        And: User password is updated in repository
        And: Audit log records password reset
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        user_repo.find_by_username.return_value = {
            "password": "old_hash",
            "email": "test@example.com",
            "role": "admin"
        }
        
        # Act
        with patch.object(PasswordService, 'is_valid_password', return_value=True), \
             patch.object(PasswordService, 'hash_password', return_value="new_hash"):
            result = auth_service.reset_password("test_user", "NewValidPassword123!")
        
        # Assert
        assert result == True
        user_repo.save_user.assert_called_once()
        audit_repo.log_event.assert_called_with("Password reset by user: test_user")
    
    def test_needs_captcha_returns_true_for_locked_account(self, auth_service_with_mocks, mock_repositories):
        """
        Test: CAPTCHA required for locked accounts
        
        Given: User account with 3+ failed attempts
        When: needs_captcha() is called
        Then: Returns True
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        attempts_repo.get_attempts.return_value = {"count": 3}
        
        # Act
        result = auth_service.needs_captcha("locked_user")
        
        # Assert
        assert result == True
    
    def test_needs_captcha_returns_false_for_normal_account(self, auth_service_with_mocks, mock_repositories):
        """
        Test: CAPTCHA not required for normal accounts
        
        Given: User account with less than 3 failed attempts
        When: needs_captcha() is called
        Then: Returns False
        """
        # Arrange
        auth_service = auth_service_with_mocks
        user_repo, attempts_repo, audit_repo = mock_repositories
        
        attempts_repo.get_attempts.return_value = {"count": 1}
        
        # Act
        result = auth_service.needs_captcha("normal_user")
        
        # Assert
        assert result == False


class TestPasswordService:
    """Test suite for password validation and hashing."""
    
    def test_valid_password_meets_complexity_requirements(self):
        """
        Test: Password validation accepts complex passwords
        
        Given: Password with 8+ chars, upper, lower, number, special
        When: is_valid_password() is called
        Then: Returns True
        """
        # Arrange & Act
        result = PasswordService.is_valid_password("ValidPass123!")
        
        # Assert
        assert result == True
    
    def test_password_too_short_fails_validation(self):
        """
        Test: Password validation rejects short passwords
        
        Given: Password with less than 8 characters
        When: is_valid_password() is called
        Then: Returns False
        """
        # Arrange & Act
        result = PasswordService.is_valid_password("Short1!")
        
        # Assert
        assert result == False
    
    def test_password_without_uppercase_fails_validation(self):
        """
        Test: Password validation rejects passwords without uppercase
        
        Given: Password without uppercase letters
        When: is_valid_password() is called
        Then: Returns False
        """
        # Arrange & Act
        result = PasswordService.is_valid_password("lowercase123!")
        
        # Assert
        assert result == False
    
    def test_password_without_number_fails_validation(self):
        """
        Test: Password validation rejects passwords without numbers
        
        Given: Password without numeric characters
        When: is_valid_password() is called
        Then: Returns False
        """
        # Arrange & Act
        result = PasswordService.is_valid_password("ValidPassword!")
        
        # Assert
        assert result == False
    
    def test_password_without_special_char_fails_validation(self):
        """
        Test: Password validation rejects passwords without special characters
        
        Given: Password without special characters
        When: is_valid_password() is called
        Then: Returns False
        """
        # Arrange & Act
        result = PasswordService.is_valid_password("ValidPassword123")
        
        # Assert
        assert result == False
    
    def test_hash_password_returns_bcrypt_hash(self):
        """
        Test: Password hashing produces bcrypt hash
        
        Given: Plain text password
        When: hash_password() is called
        Then: Returns bcrypt-formatted hash string
        """
        # Arrange & Act
        result = PasswordService.hash_password("TestPassword123!")
        
        # Assert
        assert result.startswith("$2b$")
        assert len(result) == 60  # Standard bcrypt hash length
    
    def test_verify_password_succeeds_with_correct_password(self):
        """
        Test: Password verification succeeds with correct password
        
        Given: Plain text password and matching hash
        When: verify_password() is called
        Then: Returns True
        """
        # Arrange
        password = "TestPassword123!"
        password_hash = PasswordService.hash_password(password)
        
        # Act
        result = PasswordService.verify_password(password, password_hash)
        
        # Assert
        assert result == True
    
    def test_verify_password_fails_with_incorrect_password(self):
        """
        Test: Password verification fails with incorrect password
        
        Given: Plain text password and non-matching hash
        When: verify_password() is called
        Then: Returns False
        """
        # Arrange
        correct_password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        password_hash = PasswordService.hash_password(correct_password)
        
        # Act
        result = PasswordService.verify_password(wrong_password, password_hash)
        
        # Assert
        assert result == False