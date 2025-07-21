"""File-based data repository implementations."""
import json
import os
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class Repository(ABC):
    """Abstract base repository interface."""
    
    @abstractmethod
    def find_by_id(self, id: str) -> Optional[Any]:
        """Find entity by ID."""
        pass
    
    @abstractmethod
    def save(self, entity: Any) -> None:
        """Save entity."""
        pass
    
    @abstractmethod
    def delete(self, id: str) -> bool:
        """Delete entity by ID."""
        pass


class FileRepository:
    """Base file repository for JSON data storage."""
    
    def __init__(self, filename: str, base_path: str = None):
        if base_path is None:
            # Auto-detect base path
            if os.path.exists("users.json"):
                self.base_path = "."
            else:
                self.base_path = "app"
        else:
            self.base_path = base_path
            
        self.filepath = os.path.join(self.base_path, filename)
    
    def load_data(self) -> Dict[str, Any]:
        """Load JSON data from file."""
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                return json.load(f)
        return {}
    
    def save_data(self, data: Dict[str, Any]) -> None:
        """Save JSON data to file."""
        with open(self.filepath, "w") as f:
            json.dump(data, f, indent=2)


class UserRepository(FileRepository):
    """Repository for user data operations."""
    
    def __init__(self, base_path: str = None):
        super().__init__("users.json", base_path)
    
    def find_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Find user by username."""
        users = self.load_data()
        return users.get(username)
    
    def save_user(self, username: str, user_data: Dict[str, Any]) -> None:
        """Save user data."""
        users = self.load_data()
        users[username] = user_data
        self.save_data(users)
    
    def get_all_users(self) -> Dict[str, Any]:
        """Get all users."""
        return self.load_data()
    
    def user_exists(self, username: str) -> bool:
        """Check if user exists."""
        return username in self.load_data()
    
    def delete_user(self, username: str) -> bool:
        """Delete user."""
        users = self.load_data()
        if username in users:
            del users[username]
            self.save_data(users)
            return True
        return False


class FailedAttemptsRepository(FileRepository):
    """Repository for failed login attempts."""
    
    def __init__(self, base_path: str = None):
        super().__init__("failed_attempts.json", base_path)
    
    def get_attempts(self, username: str) -> Optional[Dict[str, Any]]:
        """Get failed attempts for user."""
        attempts = self.load_data()
        return attempts.get(username)
    
    def save_attempt(self, username: str, attempt_data: Dict[str, Any]) -> None:
        """Save failed attempt data."""
        attempts = self.load_data()
        attempts[username] = attempt_data
        self.save_data(attempts)
    
    def clear_attempts(self, username: str) -> None:
        """Clear failed attempts for user."""
        attempts = self.load_data()
        if username in attempts:
            del attempts[username]
            self.save_data(attempts)
    
    def get_all_attempts(self) -> Dict[str, Any]:
        """Get all failed attempts."""
        return self.load_data()


class AuditRepository:
    """Repository for audit log operations."""
    
    def __init__(self, base_path: str = None):
        if base_path is None:
            # Auto-detect base path
            if os.path.exists("users.json"):
                self.base_path = "."
            else:
                self.base_path = "app"
        else:
            self.base_path = base_path
            
        self.filepath = os.path.join(self.base_path, "audit.log")
    
    def log_event(self, message: str) -> None:
        """Write audit log entry."""
        from datetime import datetime
        with open(self.filepath, "a") as log:
            log.write(f"[{datetime.now()}] {message}\n")
    
    def get_log_content(self) -> str:
        """Read audit log content."""
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as log:
                return log.read()
        return ""
    
    def log_exists(self) -> bool:
        """Check if audit log exists."""
        return os.path.exists(self.filepath)