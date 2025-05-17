# Azure Drift Detector Test Suite

This directory contains unit tests for the Azure Drift Detector application, ensuring that all components of the system function correctly.

## Test Structure

The test suite is organized by component:

- `test_models.py` - Tests for database models and relationships
- `test_auth.py` - Tests for authentication and user management
- `test_drift_detector.py` - Tests for the drift detection algorithm
- `test_api.py` - Tests for API endpoints
- `test_routes.py` - Tests for web routes and UI elements

## Running Tests

You can run all tests using the provided `run_tests.py` script in the root directory:

```bash
./run_tests.py
```

### Options

- Run with increased verbosity:
  ```bash
  ./run_tests.py -v
  ```

- Run a specific test file:
  ```bash
  ./run_tests.py -t test_models.py
  ```

## Test Database

Tests use an in-memory SQLite database by default, which is created and destroyed during each test run. This ensures that tests do not affect your production database.

If you need to use a different database for testing, you can set the `SQLALCHEMY_DATABASE_URI` environment variable.

## Test Coverage

The test suite aims to provide comprehensive coverage of the application:

1. **Database Models**: Testing CRUD operations, relationships, and model methods
2. **Authentication**: Testing login, permissions, and role-based access control
3. **Drift Detection**: Testing drift detection logic and severity determination
4. **API Endpoints**: Testing all API endpoints with different permissions
5. **Web Routes**: Testing web pages and form submissions

## Adding New Tests

When adding new features to the application, follow these guidelines for writing tests:

1. Place tests in the appropriate file based on the component being tested
2. Use descriptive test names that explain what is being tested
3. Include both positive tests (expected behavior) and negative tests (error handling)
4. Use fixtures from `conftest.py` when possible to avoid duplicating setup code

## Continuous Integration

These tests can be easily integrated into a CI/CD pipeline to ensure code quality before deployment.