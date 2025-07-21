# Clinical Timeline App - Test Suite

## Overview
Comprehensive test suite for the Clinical Timeline application using pytest framework with clean service layer architecture.

## Test Categories

### Unit Tests (`tests/unit/`)
Test individual components in isolation with mocked dependencies. These tests are fast and focus on business logic without external dependencies.

- **`test_auth_service.py`** - Authentication and user management business logic
- **`test_timeline_service.py`** - Timeline data processing and chart generation  
- **`test_captcha_service.py`** - CAPTCHA generation and validation
- **`test_password_service.py`** - Password validation and hashing
- **`test_repositories.py`** - Data access layer operations

### Integration Tests (`tests/integration/`)
Test multiple components working together with real data persistence. These tests verify that different layers of the application work correctly together.

- **`test_user_workflow.py`** - Complete user lifecycle (create → login → use → logout)
- **`test_auth_flow.py`** - Authentication flow with real file persistence
- **`test_data_persistence.py`** - File operations and data consistency

### UI Tests (`tests/ui/`)
Test Streamlit UI components with mocked services. These tests verify UI behavior and user interactions.

- **`test_login_page.py`** - Login form behavior and session management
- **`test_admin_page.py`** - Admin panel functionality and permissions
- **`test_timeline_page.py`** - Timeline visualization and interactions

## Installation

### 1. Install Test Dependencies
```bash
pip install -r requirements-test.txt
```

### 2. Verify Installation
```bash
pytest --version
```

## Running Tests

### All Tests
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=app.service_layer --cov-report=html
```

### Specific Categories
```bash
# Unit tests only (fast)
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# UI tests only  
pytest tests/ui/
```

### Specific Test Files
```bash
# Authentication service tests
pytest tests/unit/test_auth_service.py

# Timeline functionality tests
pytest tests/unit/test_timeline_service.py

# User workflow integration tests
pytest tests/integration/test_user_workflow.py
```

### Specific Test Methods
```bash
# Run single test method
pytest tests/unit/test_auth_service.py::TestAuthenticationService::test_successful_authentication

# Run all tests in a class
pytest tests/unit/test_auth_service.py::TestAuthenticationService
```

## Test Configuration

### Environment Setup
Tests use temporary files and directories to avoid interfering with application data:
- **Unit tests**: Use mocked repositories (no file I/O)
- **Integration tests**: Use temporary directories for real file operations
- **UI tests**: Mock Streamlit session state

### Fixtures
Common test fixtures are defined in `conftest.py`:
- `temp_directory`: Temporary directory for test files
- `mock_repositories`: Mocked data access objects
- `real_repositories`: Real repositories with temporary storage
- `sample_user`: Test user object
- `auth_service_with_mocks`: Pre-configured service with mocks

## Test Data
Test fixtures and sample data are stored in `tests/fixtures/`:
- `sample_users.json`: Sample user data for testing
- `sample_timeline_data.json`: Sample clinical timeline data
- `test_config.py`: Test configuration settings

## Coverage Reports

### Generate HTML Coverage Report
```bash
pytest --cov=app.service_layer --cov-report=html
```
View results in `htmlcov/index.html`

### Coverage Targets
- **Unit Tests**: 90%+ coverage of service layer business logic
- **Integration Tests**: 80%+ coverage of cross-layer interactions
- **UI Tests**: 70%+ coverage of UI components

## Best Practices

### Writing Tests
1. **Use descriptive test names**: `test_successful_authentication_returns_user_object`
2. **Follow AAA pattern**: Arrange → Act → Assert
3. **One assertion per test**: Focus on single behavior
4. **Use fixtures**: Reuse common setup code
5. **Mock external dependencies**: Keep tests fast and isolated

### Test Organization
1. **Group related tests**: Use test classes to group related functionality
2. **Use clear docstrings**: Explain what each test verifies
3. **Keep tests simple**: Tests should be easy to understand
4. **Avoid test interdependence**: Each test should run independently

### Example Test Structure
```python
def test_feature_description_expected_behavior(self):
    \"\"\"
    Test: Brief description of what is being tested
    
    Given: Initial conditions
    When: Action being performed  
    Then: Expected outcome
    \"\"\"
    # Arrange
    # Act  
    # Assert
```

## Continuous Integration

### GitHub Actions (Recommended)
```yaml
# .github/workflows/tests.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - run: pip install -r requirements-test.txt
      - run: pytest --cov=app.service_layer
```

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Add app directory to Python path
export PYTHONPATH="${PYTHONPATH}:${PWD}/app"
pytest
```

**Streamlit Import Issues**
```bash
# Install streamlit for UI tests
pip install streamlit
```

**File Permission Issues**
```bash
# Ensure test directory is writable
chmod -R 755 tests/
```

### Debug Mode
```bash
# Run tests with debug output
pytest -s -v --tb=long

# Run specific test with detailed output
pytest tests/unit/test_auth_service.py -s -v
```

## Contributing

### Adding New Tests
1. Create test file in appropriate directory (`unit/`, `integration/`, `ui/`)
2. Import necessary fixtures from `conftest.py`
3. Follow naming convention: `test_*.py`
4. Add docstrings explaining test purpose
5. Update this README if adding new test categories

### Code Coverage
- Aim for high coverage of business logic (services)
- Focus on critical paths and edge cases
- Don't chase 100% coverage at expense of test quality

## Related Documentation
- [Architecture Comparison](../docs/architecture-comparison.md)
- [Mobile Architecture Recommendations](../docs/mobile-architecture-recommendations.md)
- [Service Layer Implementation](../app/service_layer/)