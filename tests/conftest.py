"""
Shared pytest fixtures and configuration.

This file contains reusable test fixtures that can be used across
multiple test files. Fixtures defined here are automatically available
to all tests without explicit imports.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock
from service_layer.repositories import UserRepository, FailedAttemptsRepository, AuditRepository
from service_layer.services import AuthenticationService, TimelineDataService, CaptchaService
from service_layer.models import User


@pytest.fixture
def temp_directory():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


@pytest.fixture
def mock_user_repository():
    """Mock user repository for isolated testing."""
    return Mock(spec=UserRepository)


@pytest.fixture
def mock_failed_attempts_repository():
    """Mock failed attempts repository for isolated testing."""
    return Mock(spec=FailedAttemptsRepository)


@pytest.fixture
def mock_audit_repository():
    """Mock audit repository for isolated testing."""
    return Mock(spec=AuditRepository)


@pytest.fixture
def mock_repositories(mock_user_repository, mock_failed_attempts_repository, mock_audit_repository):
    """Bundle of all mock repositories."""
    return mock_user_repository, mock_failed_attempts_repository, mock_audit_repository


@pytest.fixture
def real_repositories(temp_directory):
    """Real repositories using temporary files for integration tests."""
    user_repo = UserRepository(base_path=temp_directory)
    attempts_repo = FailedAttemptsRepository(base_path=temp_directory)
    audit_repo = AuditRepository(base_path=temp_directory)
    return user_repo, attempts_repo, audit_repo


@pytest.fixture
def auth_service_with_mocks(mock_repositories):
    """AuthenticationService with mocked dependencies."""
    user_repo, attempts_repo, audit_repo = mock_repositories
    return AuthenticationService(user_repo, attempts_repo, audit_repo)


@pytest.fixture
def auth_service_with_real_repos(real_repositories):
    """AuthenticationService with real repositories for integration tests."""
    user_repo, attempts_repo, audit_repo = real_repositories
    return AuthenticationService(user_repo, attempts_repo, audit_repo)


@pytest.fixture
def sample_user():
    """Sample user object for testing."""
    return User(
        username="test_user",
        email="test@example.com", 
        role="admin",
        password_hash="$2b$12$sample_hash"
    )


@pytest.fixture
def sample_user_data():
    """Sample user data dictionary for repository tests."""
    return {
        "password": "$2b$12$sample_hash",
        "email": "test@example.com",
        "role": "admin"
    }


@pytest.fixture
def timeline_service():
    """TimelineDataService for testing."""
    return TimelineDataService()


@pytest.fixture
def captcha_service():
    """CaptchaService for testing."""
    return CaptchaService()


@pytest.fixture(autouse=True)
def reset_streamlit_session():
    """Reset Streamlit session state before each test."""
    import streamlit as st
    # Clear session state before each test
    for key in list(st.session_state.keys()):
        del st.session_state[key]