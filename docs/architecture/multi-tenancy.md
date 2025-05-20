# Multi-tenancy Design

## Overview

The Azure Drift Detector implements a multi-tenant architecture that allows multiple organizations to use the system while maintaining data isolation and security. This document outlines the multi-tenancy design and implementation details.

## Tenant Model

### Tenant Organization
- Each tenant represents a distinct organization
- Tenants are isolated at the data layer
- Each tenant has its own:
  - Users and roles
  - Azure subscriptions
  - Configuration baselines
  - Drift detection settings

### Tenant Isolation

1. **Data Isolation**
   - All models include a `tenant_id` field
   - Database queries are automatically scoped to the current tenant
   - Cross-tenant data access is prevented at the application layer

2. **Authentication & Authorization**
   - Users are associated with specific tenants
   - Role-based access control is tenant-scoped
   - Azure AD integration supports tenant-specific authentication

3. **Resource Management**
   - Azure resources are organized by tenant
   - Each tenant can manage their own Azure subscriptions
   - Resource polling and drift detection are tenant-isolated

## Implementation Details

### Database Schema

```sql
-- Tenant table
CREATE TABLE tenant (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    azure_tenant_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add tenant_id to existing tables
ALTER TABLE user ADD COLUMN tenant_id INTEGER REFERENCES tenant(id);
ALTER TABLE configuration ADD COLUMN tenant_id INTEGER REFERENCES tenant(id);
ALTER TABLE configuration_history ADD COLUMN tenant_id INTEGER REFERENCES tenant(id);
ALTER TABLE settings ADD COLUMN tenant_id INTEGER REFERENCES tenant(id);
```

### Tenant Context

The application maintains tenant context through:
1. User session
2. API request headers
3. Database query filters

### Security Considerations

1. **Data Access**
   - All database queries must include tenant_id
   - Middleware enforces tenant context
   - API endpoints validate tenant access

2. **User Management**
   - Users can only access their assigned tenant
   - Role permissions are tenant-scoped
   - Cross-tenant user management is restricted

3. **Azure Integration**
   - Azure credentials are tenant-specific
   - Resource access is limited to tenant's subscriptions
   - API calls are authenticated per tenant
ddfsdafadsf
## Tenant Management

### Provisioning
1. Create new tenant record
2. Set up tenant-specific settings
3. Configure Azure integration
4. Create initial admin user

### Configuration
- Tenant-specific drift detection rules
- Custom notification settings
- Resource monitoring preferences

### Monitoring
- Tenant-specific metrics
- Usage statistics
- Resource consumption

## Best Practices

1. **Data Management**
   - Regular tenant data cleanup
   - Tenant-specific backups
   - Data retention policies

2. **Performance**
   - Tenant-specific caching
   - Resource usage monitoring
   - Query optimization

3. **Security**
   - Regular security audits
   - Tenant isolation testing
   - Access control reviews 