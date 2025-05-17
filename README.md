#Savanna Tech  Azure Drift Detector

A Flask-based web application that monitors and detects configuration changes (drift) in Azure resources. The application helps identify potential security risks and configuration changes in your Azure infrastructure.

## Features

- **Automated Drift Detection**: Monitors Azure resource configurations and detects changes automatically
- **Severity Classification**: Classifies configuration changes into different severity levels (critical, high, medium, low)
- **Security-Focused**: Special attention to security-sensitive configuration changes
- **Dashboard**: Real-time overview of resource changes and critical alerts
- **Authentication**: Secure user authentication and role-based access control
- **API Support**: RESTful API with Swagger documentation
- **Automated Polling**: Background scheduler to poll Azure configurations every 30 minutes

## Installation

1. Clone the repository:
```bash
git clone https://github.com/joekabucho/savanna-tech-azure-drift-detector.git
cd savanna-tech-azure-drift-detector
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# Required environment variables
export DATABASE_URL="postgresql://user:password@localhost/dbname"  # Optional: defaults to SQLite
export SESSION_SECRET="your-secret-key"
```

5. Initialize the database:
```bash
flask db upgrade
```

## Usage

1. Start the application:
```bash
python main.py
```

2. Access the web interface at `http://localhost:5000`

3. Log in with your credentials

4. View the dashboard to monitor Azure resource changes

### Test Users (Non-OIDC)

For testing purposes, the following default users are available when not using OIDC:

- **Admin User**
  - Username: `admin`
  - Password: `adminpass`
  - Role: Full system access

- **Operator User**
  - Username: `operator`
  - Password: `operatorpass`
  - Role: Operations access

- **Regular User**
  - Username: `user`
  - Password: `userpass`
  - Role: Basic access

> **Note**: These credentials are for testing purposes only. In production, please use proper authentication methods and secure credentials.

## Configuration Monitoring

The application monitors various Azure resource configurations, including:

- Security settings
- Network security rules
- Identity and authentication settings
- Encryption settings
- Access control configurations
- Backup and recovery settings
- Compliance and governance settings
- Connectivity and networking configurations

### Severity Levels

Changes are classified into four severity levels:

- **Critical**: Changes that could directly impact security (e.g., network access rules, authentication settings)
- **High**: Important security-related changes (e.g., encryption settings, security profiles)
- **Medium**: Significant operational changes (e.g., SKU changes, backup retention)
- **Low**: Minor configuration changes

## API Documentation

The API documentation is available through Swagger UI at `http://localhost:5000/api/docs/` when the application is running. This interactive documentation provides detailed information about all available endpoints, request/response formats, and allows you to test the API directly from your browser.

## Development

### Project Structure

- `app.py`: Main application configuration and initialization
- `drift_detector.py`: Core drift detection logic
- `azure_poller.py`: Azure configuration polling service
- `models.py`: Database models
- `routes.py`: Web routes and controllers
- `auth.py`: Authentication and authorization
- `api.py`: API endpoints
- `templates/`: HTML templates
- `static/`: Static assets
- `migrations/`: Database migrations

### Running Tests

```bash
python run_tests.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

