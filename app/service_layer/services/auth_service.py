"""Authentication service - pure business logic, no UI dependencies."""
import bcrypt
import re
from datetime import datetime
from typing import Optional
from ..models import User, LoginAttempt, AuthenticationResult
from ..repositories import UserRepository, FailedAttemptsRepository, AuditRepository


class PasswordService:
    """Service for password operations."""
    
    @staticmethod
    def is_valid_password(password: str) -> bool:
        """Validate password complexity."""
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode(), hashed.encode())


class AuthenticationService:
    """Pure business logic for authentication - no Streamlit dependencies."""
    
    def __init__(self, user_repo: UserRepository, attempts_repo: FailedAttemptsRepository, 
                 audit_repo: AuditRepository):
        self.user_repo = user_repo
        self.attempts_repo = attempts_repo
        self.audit_repo = audit_repo
        self.password_service = PasswordService()
    
    def authenticate(self, username: str, password: str) -> AuthenticationResult:
        """Authenticate user credentials."""
        # Check if account is locked
        if self._is_account_locked(username):
            return AuthenticationResult(
                success=False,
                error_message="Account locked due to multiple failed attempts",
                requires_captcha=True
            )
        
        # Get user data
        user_data = self.user_repo.find_by_username(username)
        if not user_data:
            self._record_failed_attempt(username)
            self.audit_repo.log_event(f"Failed login attempt for non-existent username: {username}")
            return AuthenticationResult(
                success=False,
                error_message="Invalid username or password"
            )
        
        # Verify password
        if self.password_service.verify_password(password, user_data["password"]):
            # Success - clear failed attempts and create user object
            self.attempts_repo.clear_attempts(username)
            user = User(
                username=username,
                email=user_data["email"],
                role=user_data["role"],
                password_hash=user_data["password"]
            )
            self.audit_repo.log_event(f"Successful login: {username}")
            return AuthenticationResult(success=True, user=user)
        else:
            # Failed password
            self._record_failed_attempt(username)
            self.audit_repo.log_event(f"Failed login attempt for username: {username}")
            return AuthenticationResult(
                success=False,
                error_message="Invalid username or password",
                requires_captcha=self._is_account_locked(username)
            )
    
    def reset_password(self, username: str, new_password: str) -> bool:
        """Reset user password."""
        if not self.password_service.is_valid_password(new_password):
            return False
        
        user_data = self.user_repo.find_by_username(username)
        if not user_data:
            return False
        
        user_data["password"] = self.password_service.hash_password(new_password)
        self.user_repo.save_user(username, user_data)
        self.audit_repo.log_event(f"Password reset by user: {username}")
        return True
    
    def create_user(self, username: str, email: str, password: str, role: str) -> bool:
        """Create new user."""
        if self.user_repo.user_exists(username):
            return False
        
        if not self.password_service.is_valid_password(password):
            return False
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False
        
        user_data = {
            "password": self.password_service.hash_password(password),
            "role": role,
            "email": email
        }
        self.user_repo.save_user(username, user_data)
        self.audit_repo.log_event(f"User created: {username} ({role})")
        return True
    
    def update_user(self, username: str, email: str = None, role: str = None) -> bool:
        """Update user information."""
        user_data = self.user_repo.find_by_username(username)
        if not user_data:
            return False
        
        if email:
            user_data["email"] = email
        if role:
            user_data["role"] = role
        
        self.user_repo.save_user(username, user_data)
        self.audit_repo.log_event(f"Updated user info: {username}, role={role}, email={email}")
        return True
    
    def admin_reset_password(self, target_username: str, new_password: str, admin_username: str) -> bool:
        """Admin reset of user password."""
        if not self.password_service.is_valid_password(new_password):
            return False
        
        user_data = self.user_repo.find_by_username(target_username)
        if not user_data:
            return False
        
        user_data["password"] = self.password_service.hash_password(new_password)
        self.user_repo.save_user(target_username, user_data)
        self.audit_repo.log_event(f"Admin {admin_username} reset password for user: {target_username}")
        return True
    
    def unlock_user(self, username: str, admin_username: str) -> bool:
        """Unlock user account."""
        attempts = self.attempts_repo.get_attempts(username)
        if attempts:
            self.attempts_repo.clear_attempts(username)
            self.audit_repo.log_event(f"Admin {admin_username} unlocked user: {username}")
            return True
        return False
    
    def get_all_users(self) -> dict:
        """Get all users data."""
        return self.user_repo.get_all_users()
    
    def get_locked_users(self) -> list:
        """Get list of locked usernames."""
        all_attempts = self.attempts_repo.get_all_attempts()
        return [user for user, info in all_attempts.items() if info.get('count', 0) >= 3]
    
    def needs_captcha(self, username: str) -> bool:
        """Check if user needs CAPTCHA."""
        return self._is_account_locked(username)
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        attempts = self.attempts_repo.get_attempts(username)
        return attempts and attempts.get("count", 0) >= 3
    
    def _record_failed_attempt(self, username: str) -> None:
        """Record a failed login attempt."""
        attempts = self.attempts_repo.get_attempts(username)
        if attempts:
            count = attempts.get("count", 0) + 1
        else:
            count = 1
        
        attempt_data = {
            "count": count,
            "last_attempt": datetime.now().isoformat()
        }
        self.attempts_repo.save_attempt(username, attempt_data)