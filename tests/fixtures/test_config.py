"""
Test Configuration Settings

Shared configuration and constants for test suite.
"""

# Test user credentials (for integration tests)
TEST_USERS = {
    "admin": {
        "username": "test_admin",
        "password": "TestAdmin123!",
        "email": "admin@test.example.com",
        "role": "admin"
    },
    "viewer": {
        "username": "test_viewer", 
        "password": "TestViewer123!",
        "email": "viewer@test.example.com",
        "role": "viewer"
    }
}

# Test password validation cases
VALID_PASSWORDS = [
    "ValidPass123!",
    "AnotherGood1@",
    "Complex123#Pass",
    "Strong99$Word"
]

INVALID_PASSWORDS = [
    "short",           # Too short
    "nouppercase123!", # No uppercase
    "NOLOWERCASE123!", # No lowercase
    "NoNumbers!",      # No numbers
    "NoSpecialChars123" # No special characters
]

# Test timeline data constants
SAMPLE_PATIENT_ID = "test_patient_001"

# File paths for test fixtures
FIXTURES_DIR = "tests/fixtures"
SAMPLE_USERS_FILE = f"{FIXTURES_DIR}/sample_users.json"
SAMPLE_TIMELINE_FILE = f"{FIXTURES_DIR}/sample_timeline_data.json"

# CAPTCHA test cases
CAPTCHA_TEST_CASES = [
    (1, 1, "2", True),   # Minimum values
    (5, 7, "12", True),  # Mid-range values
    (9, 9, "18", True),  # Maximum values
    (3, 4, "8", False),  # Wrong answer
    (2, 6, "abc", False), # Non-numeric
    (4, 5, "", False),   # Empty string
    (1, 8, " 9 ", True), # Whitespace (should work)
]

# Audit log test patterns
AUDIT_PATTERNS = {
    "user_created": r"\[.*\] User created: .* \(.*\)",
    "successful_login": r"\[.*\] Successful login: .*",
    "failed_login": r"\[.*\] Failed login attempt for username: .*",
    "password_reset": r"\[.*\] Password reset by user: .*",
    "admin_password_reset": r"\[.*\] Admin .* reset password for user: .*",
    "user_unlocked": r"\[.*\] Admin .* unlocked user: .*",
    "user_updated": r"\[.*\] Updated user info: .*"
}

# Performance thresholds for integration tests
PERFORMANCE_THRESHOLDS = {
    "max_login_time_ms": 1000,
    "max_chart_generation_time_ms": 2000,
    "max_file_operation_time_ms": 500
}

# Mock data for UI tests
MOCK_USER_DATA = {
    "test_user": {
        "password": "$2b$12$mock_hash",
        "email": "mock@example.com",
        "role": "admin"
    }
}

MOCK_FAILED_ATTEMPTS = {
    "locked_user": {
        "count": 3,
        "last_attempt": "2024-01-01T10:00:00"
    }
}

# Test environment settings
TEST_ENV = {
    "temp_file_prefix": "clinical_timeline_test_",
    "cleanup_temp_files": True,
    "log_test_operations": False
}