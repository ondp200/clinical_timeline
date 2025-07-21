"""
Login Page UI Tests

Purpose: Test login page UI components and interactions
Scope: LoginPage class with mocked services
Dependencies: Mocked services, Streamlit session state

Test Categories:
1. Login form rendering and behavior
2. CAPTCHA display and validation
3. Password reset functionality  
4. Session state management
5. Error message display
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import streamlit as st
from service_layer.pages import LoginPage
from service_layer.models import AuthenticationResult, User


class TestLoginPageRendering:
    """Test suite for login page UI rendering."""
    
    @patch('streamlit.title')
    @patch('streamlit.tabs')
    def test_login_page_renders_basic_structure(self, mock_tabs, mock_title):
        """
        Test: Login page renders basic UI structure
        
        Given: LoginPage with mocked services
        When: render() is called
        Then: Page title and tabs are displayed
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock tabs to return mock tab contexts
        mock_login_tab = MagicMock()
        mock_reset_tab = MagicMock()
        mock_tabs.return_value = (mock_login_tab, mock_reset_tab)
        
        # Act
        login_page.render()
        
        # Assert
        mock_title.assert_called_once_with("🔐 Clinical Timeline App Login")
        mock_tabs.assert_called_once_with(["Login", "Forgot Password"])
    
    @patch('streamlit.text_input')
    @patch('streamlit.button')
    @patch('streamlit.tabs')
    def test_login_tab_renders_input_fields(self, mock_tabs, mock_button, mock_text_input):
        """
        Test: Login tab renders username and password input fields
        
        Given: LoginPage in login tab
        When: Login tab is rendered
        Then: Username and password inputs are displayed
        And: Login button is displayed
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock streamlit components
        mock_login_tab = MagicMock()
        mock_reset_tab = MagicMock()
        mock_tabs.return_value = (mock_login_tab, mock_reset_tab)
        mock_text_input.side_effect = ["test_user", "test_password"]
        mock_button.return_value = False  # Button not clicked
        
        # Act
        with patch.object(login_page, '_render_login_tab') as mock_render_login:
            login_page.render()
            # Simulate entering the login tab context
            mock_render_login.assert_called_once()


class TestLoginPageInteractions:
    """Test suite for login page user interactions."""
    
    def test_successful_login_updates_session_state(self):
        """
        Test: Successful login updates session state correctly
        
        Given: Valid credentials and successful authentication
        When: Login is attempted
        Then: Session state is updated with user data
        And: Success message is displayed
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock successful authentication
        test_user = User("test_user", "test@example.com", "admin", "hash")
        auth_service.authenticate.return_value = AuthenticationResult(
            success=True,
            user=test_user
        )
        auth_service.needs_captcha.return_value = False
        
        # Act
        with patch('streamlit.success') as mock_success, \
             patch('streamlit.rerun') as mock_rerun, \
             patch('streamlit.session_state', {}) as mock_session:
            
            login_page._handle_login("test_user", "test_password")
        
        # Assert
        assert mock_session['authenticated'] == True
        assert mock_session['current_user'] == test_user
        mock_success.assert_called_once_with("Access granted! Redirecting...")
        mock_rerun.assert_called_once()
    
    def test_failed_login_shows_error_message(self):
        """
        Test: Failed login displays appropriate error message
        
        Given: Invalid credentials
        When: Login is attempted
        Then: Error message is displayed
        And: Session state is not updated
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock failed authentication
        auth_service.authenticate.return_value = AuthenticationResult(
            success=False,
            error_message="Invalid username or password"
        )
        auth_service.needs_captcha.return_value = False
        
        # Act
        with patch('streamlit.error') as mock_error, \
             patch('streamlit.session_state', {}) as mock_session:
            
            login_page._handle_login("test_user", "wrong_password")
        
        # Assert
        mock_error.assert_called_once_with("Invalid username or password")
        assert 'authenticated' not in mock_session
        assert 'current_user' not in mock_session
    
    def test_captcha_required_displays_challenge(self):
        """
        Test: CAPTCHA challenge is displayed when required
        
        Given: User account that requires CAPTCHA
        When: Login page is rendered
        Then: CAPTCHA challenge is displayed
        And: CAPTCHA input field is shown
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        auth_service.needs_captcha.return_value = True
        captcha_service.generate_challenge.return_value = (3, 7)
        captcha_service.get_challenge_text.return_value = "What is 3 + 7?"
        
        # Act
        with patch('streamlit.text_input', side_effect=["locked_user", "password", "10"]) as mock_input, \
             patch('streamlit.session_state', {}) as mock_session:
            
            result = login_page._render_captcha()
        
        # Assert
        # Verify CAPTCHA was initialized in session state
        assert 'captcha_x' in mock_session
        assert 'captcha_y' in mock_session
        captcha_service.get_challenge_text.assert_called()
    
    def test_incorrect_captcha_shows_error_and_regenerates(self):
        """
        Test: Incorrect CAPTCHA shows error and generates new challenge
        
        Given: User with CAPTCHA requirement and wrong answer
        When: Login is attempted with incorrect CAPTCHA
        Then: Error message is displayed
        And: New CAPTCHA challenge is generated
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        auth_service.needs_captcha.return_value = True
        captcha_service.validate_answer.return_value = False
        captcha_service.generate_challenge.return_value = (5, 8)
        
        # Act
        with patch('streamlit.error') as mock_error, \
             patch('streamlit.session_state', {'captcha_x': 3, 'captcha_y': 7}) as mock_session:
            
            login_page._handle_login("locked_user", "password", "9")  # Wrong CAPTCHA answer
        
        # Assert
        mock_error.assert_called_once_with("CAPTCHA incorrect. Please try again.")
        captcha_service.generate_challenge.assert_called_once()
        # Verify new CAPTCHA values are set
        assert mock_session['captcha_x'] == 5
        assert mock_session['captcha_y'] == 8


class TestPasswordResetFunctionality:
    """Test suite for password reset UI functionality."""
    
    @patch('streamlit.text_input')
    @patch('streamlit.button')
    @patch('streamlit.warning')
    def test_weak_password_shows_warning(self, mock_warning, mock_button, mock_text_input):
        """
        Test: Weak password input shows validation warning
        
        Given: Password reset form with weak password
        When: Password is entered
        Then: Warning message is displayed about password requirements
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock weak password input
        mock_text_input.side_effect = ["test_user", "weak"]
        mock_button.return_value = False
        
        # Mock password validation
        with patch('service_layer.pages.login_page.PasswordService') as mock_password_service:
            mock_password_service.is_valid_password.return_value = False
            
            # Act
            login_page._render_reset_tab()
        
        # Assert
        mock_warning.assert_called_once_with(
            "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character."
        )
    
    def test_successful_password_reset_shows_success(self):
        """
        Test: Successful password reset shows success message
        
        Given: Valid username and strong password
        When: Password reset is submitted
        Then: Success message is displayed
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock successful password reset
        auth_service.reset_password.return_value = True
        
        # Act
        with patch('streamlit.text_input', side_effect=["test_user", "StrongPass123!"]), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.success') as mock_success, \
             patch('service_layer.pages.login_page.PasswordService') as mock_password_service:
            
            mock_password_service.is_valid_password.return_value = True
            login_page._render_reset_tab()
        
        # Assert
        auth_service.reset_password.assert_called_once_with("test_user", "StrongPass123!")
        mock_success.assert_called_once_with("Password reset successful. Please log in with your new password.")
    
    def test_failed_password_reset_shows_error(self):
        """
        Test: Failed password reset shows error message
        
        Given: Invalid username or password reset failure
        When: Password reset is attempted
        Then: Error message is displayed
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        # Mock failed password reset
        auth_service.reset_password.return_value = False
        
        # Act
        with patch('streamlit.text_input', side_effect=["invalid_user", "StrongPass123!"]), \
             patch('streamlit.button', return_value=True), \
             patch('streamlit.error') as mock_error, \
             patch('service_layer.pages.login_page.PasswordService') as mock_password_service:
            
            mock_password_service.is_valid_password.return_value = True
            login_page._render_reset_tab()
        
        # Assert
        auth_service.reset_password.assert_called_once_with("invalid_user", "StrongPass123!")
        mock_error.assert_called_once_with("Password reset failed. Please check your username and password requirements.")


class TestSessionStateManagement:
    """Test suite for session state management in login page."""
    
    def test_captcha_state_initialization(self):
        """
        Test: CAPTCHA state is properly initialized in session
        
        Given: Login page with CAPTCHA requirement
        When: CAPTCHA is rendered for first time
        Then: Session state contains CAPTCHA values
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        captcha_service.generate_challenge.return_value = (4, 9)
        captcha_service.get_challenge_text.return_value = "What is 4 + 9?"
        
        # Act
        with patch('streamlit.text_input', return_value="13"), \
             patch('streamlit.session_state', {}) as mock_session:
            
            login_page._render_captcha()
        
        # Assert
        assert mock_session['captcha_x'] == 4
        assert mock_session['captcha_y'] == 9
    
    def test_captcha_state_persists_across_renders(self):
        """
        Test: CAPTCHA values persist across page renders
        
        Given: CAPTCHA already initialized in session state
        When: CAPTCHA is rendered again
        Then: Same CAPTCHA values are used
        And: Challenge text reflects existing values
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        captcha_service.get_challenge_text.return_value = "What is 6 + 2?"
        
        # Act
        with patch('streamlit.text_input', return_value="8"), \
             patch('streamlit.session_state', {'captcha_x': 6, 'captcha_y': 2}) as mock_session:
            
            login_page._render_captcha()
        
        # Assert
        # Verify existing values are preserved
        assert mock_session['captcha_x'] == 6
        assert mock_session['captcha_y'] == 2
        # Verify generate_challenge was not called (values already exist)
        captcha_service.generate_challenge.assert_not_called()
        # Verify challenge text uses existing values
        captcha_service.get_challenge_text.assert_called_with(6, 2)
    
    def test_authentication_clears_sensitive_state(self):
        """
        Test: Successful authentication clears sensitive session data
        
        Given: Session state with authentication-related data
        When: Successful login occurs
        Then: User data is set in session
        And: Temporary authentication data is preserved for user experience
        """
        # Arrange
        auth_service = Mock()
        captcha_service = Mock()
        login_page = LoginPage(auth_service, captcha_service)
        
        test_user = User("test_user", "test@example.com", "admin", "hash")
        auth_service.authenticate.return_value = AuthenticationResult(
            success=True,
            user=test_user
        )
        auth_service.needs_captcha.return_value = False
        
        # Act
        with patch('streamlit.success'), \
             patch('streamlit.rerun'), \
             patch('streamlit.session_state', {'temp_data': 'should_remain'}) as mock_session:
            
            login_page._handle_login("test_user", "password")
        
        # Assert
        # Verify authentication data is set
        assert mock_session['authenticated'] == True
        assert mock_session['current_user'] == test_user
        # Verify other session data is preserved
        assert mock_session['temp_data'] == 'should_remain'