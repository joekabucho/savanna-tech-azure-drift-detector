# System Architecture Overview

## High-Level Architecture

The Azure Drift Detector is designed as a multi-tenant application that monitors and detects configuration drift in Azure resources. The system follows a modular, layered architecture:

```
┌─────────────────┐
│   Web Layer     │  Flask-based web interface and API endpoints
├─────────────────┤
│  Service Layer  │  Business logic and drift detection services
├─────────────────┤
│  Data Layer     │  Database models and data access
└─────────────────┘
```

## Key Components

### API Layer (`src/api/`)
- RESTful API endpoints
- Swagger/OpenAPI documentation
- Request validation and response formatting

### Authentication (`src/auth/`)
- User authentication and authorization
- Role-based access control
- Microsoft Azure AD integration

### Core (`src/core/`)
- Application configuration
- Database models
- Shared utilities

### Drift Detection (`src/drift/`)
- Azure resource polling
- Configuration comparison
- Drift detection algorithms

## Design Decisions

1. **Modular Architecture**
   - Separation of concerns through logical package structure
   - Each module has clear responsibilities and interfaces
   - Easy to extend and maintain

2. **Multi-tenancy**
   - Tenant isolation at the data layer
   - Role-based access control per tenant
   - Configurable tenant-specific settings

3. **Security**
   - Azure AD integration for authentication
   - Role-based access control
   - Secure credential management

4. **Scalability**
   - Stateless API design
   - Efficient database queries
   - Asynchronous processing for drift detection

## Data Flow

1. Azure resource polling collects current configurations
2. Configurations are compared against baseline
3. Drift detection algorithms identify changes
4. Changes are logged and notifications are sent
5. Users can view and manage drift through the web interface

## Future Considerations

1. **Scalability**
   - Implement caching layer
   - Add message queue for async processing
   - Consider microservices architecture for larger deployments

2. **Monitoring**
   - Add comprehensive logging
   - Implement metrics collection
   - Set up alerting system

3. **Integration**
   - Support for additional cloud providers
   - Webhook integrations
   - API extensions for custom use cases 