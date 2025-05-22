# BlindspotX Azure Drift Detector

A Flask-based web application that monitors and detects configuration changes (drift) in Azure resources. The application helps identify potential security risks and configuration changes in your Azure infrastructure.

## Features

- **Automated Drift Detection**: Monitors Azure resource configurations and detects changes automatically
- **Severity Classification**: Classifies configuration changes into different severity levels (critical, high, medium, low)
- **Security-Focused**: Special attention to security-sensitive configuration changes
- **Dashboard**: Real-time overview of resource changes and critical alerts
- **Authentication**: Secure user authentication and role-based access control
- **API Support**: RESTful API with Swagger documentation
- **Automated Polling**: Background scheduler to poll Azure configurations every 30 minutes
- **Real-time monitoring**: Continuous monitoring of Azure resources
- **Change history tracking**: Record of all configuration changes
- **Export capabilities**: Export configuration changes and history
- **User management**: Manage user roles and permissions
- **Comprehensive observability**: Use of logging, metrics, tracing, and alerting

## Observability and Monitoring

The application implements a comprehensive observability strategy using a combination of logging, metrics, tracing, and alerting.

### Logging

- **Structured JSON Logging**: All logs are in JSON format for easy parsing and analysis
- **Log Categories**:
  - Application: General application logs
  - Azure: Azure API interactions
  - Database: Database operations
  - Security: Authentication and authorization
  - Performance: Performance-related events
  - Audit: User actions and system changes
- **Log Retention**:
  - Application logs: 30 days
  - Audit logs: 1 year
  - Security logs: 1 year
  - Performance logs: 7 days

### Metrics

- **System Metrics**:
  - CPU Usage
  - Memory Usage
  - Disk I/O
  - Network I/O
  - Database Connections
- **Application Metrics**:
  - Request Rate
  - Response Time
  - Error Rate
  - Active Users
  - Resource Polling Status
- **Business Metrics**:
  - Drift Detection Rate
  - Resource Changes
  - User Actions
  - Export Operations
  - Alert Triggers

### Tracing

- **Distributed Tracing** with OpenTelemetry
- **Trace Points**:
  - HTTP Requests
  - Database Queries
  - Azure API Calls
  - Background Jobs
  - Export Operations
- **Trace Context**:
  - Request ID
  - User ID
  - Resource ID
  - Operation Type
  - Duration

### Alerting

- **Alert Levels**:
  - Info: Non-critical notifications
  - Warning: Potential issues
  - Error: Active problems
  - Critical: System failures
- **Alert Channels**:
  - Email
  - Slack
  - Azure Monitor
  - PagerDuty (optional)

## Monitoring Stack

The application uses the following monitoring tools:

1. **ELK Stack**:
   - Elasticsearch: Log storage and search
   - Logstash: Log processing
   - Kibana: Log visualization

2. **Prometheus & Grafana**:
   - Prometheus: Metrics collection
   - Grafana: Metrics visualization

3. **Jaeger**:
   - Distributed tracing
   - Performance analysis
   - Error tracking

4. **Application Insights**:
   - Azure-native monitoring
   - Performance insights
   - Error tracking

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

6. Start the monitoring stack:
```bash
# Start ELK stack
docker-compose -f monitoring/elk/docker-compose.yml up -d

# Start Prometheus and Grafana
docker-compose -f monitoring/metrics/docker-compose.yml up -d

# Start Jaeger
docker-compose -f monitoring/tracing/docker-compose.yml up -d
```

7. Run the application:
```bash
flask run
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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Check the [documentation](docs/)
2. Open an issue
3. Contact the development team

## Acknowledgments

- Azure SDK for Python
- Flask framework
- SQLAlchemy ORM
- Prometheus monitoring
- ELK Stack
- Jaeger tracing

## Running with Docker

You can run BlindspotX Azure Drift Detector using Docker and Docker Compose for easy local development and deployment.

### Prerequisites
- [Docker](https://www.docker.com/get-started) installed
- [Docker Compose](https://docs.docker.com/compose/install/) installed

### Quick Start

1. **Build and start the containers:**
   ```bash
   docker-compose up --build
   ```
   This will start both the application and a PostgreSQL database. The app will be available at [http://localhost:5000](http://localhost:5000).

2. **(Optional) Run database migrations:**
   In a new terminal, run:
   ```bash
   docker-compose exec app flask db upgrade
   ```

3. **Stop the containers:**
   ```bash
   docker-compose down
   ```

### Customization
- You can set environment variables (such as Azure credentials) in the `docker-compose.yml` file under the `app` service.
- The default database credentials are set for local development. Change them for production use.

---

