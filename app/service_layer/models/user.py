"""User data models."""
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class User:
    """User entity representing a system user."""
    username: str
    email: str
    role: str
    password_hash: str
    
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role.lower() == "admin"
    
    def is_viewer(self) -> bool:
        """Check if user has viewer role."""
        return self.role.lower() == "viewer"


@dataclass
class LoginAttempt:
    """Failed login attempt tracking."""
    username: str
    count: int
    last_attempt: datetime
    
    def is_locked(self, threshold: int = 3) -> bool:
        """Check if account is locked due to failed attempts."""
        return self.count >= threshold


@dataclass
class AuthenticationResult:
    """Result of authentication attempt."""
    success: bool
    user: Optional[User] = None
    error_message: Optional[str] = None
    requires_captcha: bool = False