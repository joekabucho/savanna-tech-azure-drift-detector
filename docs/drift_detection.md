# Drift Detection Implementation

## Overview

The drift detection system monitors Azure resources for configuration changes and classifies them based on severity and impact. This document explains the core concepts, implementation details, and configuration options.

## Core Concepts

### 1. State Management

```python
class ResourceState:
    """Represents the current state of an Azure resource."""
    
    def __init__(self, resource_id: str, resource_type: str, properties: dict):
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.properties = properties
        self.last_updated = datetime.utcnow()
        self.version = 1

    def to_dict(self) -> dict:
        """Convert state to dictionary for storage."""
        return {
            'resource_id': self.resource_id,
            'resource_type': self.resource_type,
            'properties': self.properties,
            'last_updated': self.last_updated.isoformat(),
            'version': self.version
        }
```

### 2. Change Detection

```python
class ChangeDetector:
    """Detects and classifies configuration changes."""

    def detect_changes(self, old_state: ResourceState, new_state: ResourceState) -> List[Change]:
        """
        Compare old and new states to detect changes.
        
        Args:
            old_state: Previous resource state
            new_state: Current resource state
            
        Returns:
            List of detected changes
        """
        changes = []
        
        # Compare properties
        for key, new_value in new_state.properties.items():
            old_value = old_state.properties.get(key)
            
            if old_value != new_value:
                change = self._classify_change(
                    key=key,
                    old_value=old_value,
                    new_value=new_value,
                    resource_type=new_state.resource_type
                )
                changes.append(change)
                
        return changes
```

### 3. Change Classification

```python
class ChangeClassifier:
    """Classifies changes based on severity and impact."""

    SEVERITY_RULES = {
        'security': {
            'network_security_rules': 'critical',
            'firewall_rules': 'critical',
            'access_policies': 'high',
            'encryption_settings': 'high'
        },
        'operational': {
            'sku_changes': 'medium',
            'backup_settings': 'medium',
            'monitoring_settings': 'low'
        }
    }

    def classify_change(self, change: Change) -> str:
        """
        Determine the severity of a change.
        
        Args:
            change: The detected change
            
        Returns:
            Severity level (critical, high, medium, low)
        """
        # Check security rules first
        for category, rules in self.SEVERITY_RULES.items():
            for pattern, severity in rules.items():
                if pattern in change.key.lower():
                    return severity
                    
        return 'low'  # Default severity
```

## Data Normalization

### 1. Property Normalization

```python
class PropertyNormalizer:
    """Normalizes resource properties for comparison."""

    def normalize(self, properties: dict) -> dict:
        """
        Normalize properties for consistent comparison.
        
        Args:
            properties: Raw resource properties
            
        Returns:
            Normalized properties
        """
        normalized = {}
        
        for key, value in properties.items():
            # Handle nested objects
            if isinstance(value, dict):
                normalized[key] = self.normalize(value)
            # Handle lists
            elif isinstance(value, list):
                normalized[key] = self._normalize_list(value)
            # Handle primitive types
            else:
                normalized[key] = self._normalize_value(value)
                
        return normalized

    def _normalize_list(self, items: list) -> list:
        """Normalize list items."""
        return [self.normalize(item) if isinstance(item, dict) 
                else self._normalize_value(item) for item in items]

    def _normalize_value(self, value: Any) -> Any:
        """Normalize primitive values."""
        if isinstance(value, str):
            return value.lower().strip()
        return value
```

### 2. Nested Object Handling

```python
class NestedObjectHandler:
    """Handles comparison of nested objects."""

    def compare_objects(self, old: dict, new: dict) -> List[Change]:
        """
        Compare nested objects and detect changes.
        
        Args:
            old: Old object state
            new: New object state
            
        Returns:
            List of changes
        """
        changes = []
        
        # Compare all keys in both objects
        all_keys = set(old.keys()) | set(new.keys())
        
        for key in all_keys:
            old_value = old.get(key)
            new_value = new.get(key)
            
            # Handle nested objects
            if isinstance(old_value, dict) and isinstance(new_value, dict):
                nested_changes = self.compare_objects(old_value, new_value)
                changes.extend(nested_changes)
            # Handle lists
            elif isinstance(old_value, list) and isinstance(new_value, list):
                list_changes = self._compare_lists(key, old_value, new_value)
                changes.extend(list_changes)
            # Handle primitive values
            elif old_value != new_value:
                changes.append(Change(
                    key=key,
                    old_value=old_value,
                    new_value=new_value
                ))
                
        return changes
```

## Configuration Options

### 1. Detection Thresholds

```python
DETECTION_CONFIG = {
    'min_change_interval': 300,  # 5 minutes
    'max_changes_per_hour': 100,
    'ignored_properties': [
        'last_updated',
        'system_metadata',
        'tags'
    ],
    'sensitive_properties': [
        'password',
        'secret',
        'key',
        'token'
    ]
}
```

### 2. Severity Thresholds

```python
SEVERITY_THRESHOLDS = {
    'critical': {
        'max_changes_per_hour': 10,
        'notification_channels': ['email', 'slack', 'pagerduty'],
        'auto_remediation': True
    },
    'high': {
        'max_changes_per_hour': 20,
        'notification_channels': ['email', 'slack'],
        'auto_remediation': False
    },
    'medium': {
        'max_changes_per_hour': 50,
        'notification_channels': ['slack'],
        'auto_remediation': False
    },
    'low': {
        'max_changes_per_hour': 100,
        'notification_channels': [],
        'auto_remediation': False
    }
}
```

## Implementation Details

### 1. Change Detection Process

1. **State Collection**
   - Poll Azure resources
   - Normalize properties
   - Store current state

2. **Change Detection**
   - Compare with previous state
   - Normalize differences
   - Classify changes

3. **Change Processing**
   - Apply severity rules
   - Generate notifications
   - Update history

### 2. Performance Considerations

- Use batch processing for large resources
- Implement caching for frequent comparisons
- Optimize database queries
- Use async processing for notifications

### 3. Error Handling

```python
class DriftDetectionError(Exception):
    """Base exception for drift detection errors."""
    pass

class StateCollectionError(DriftDetectionError):
    """Error during state collection."""
    pass

class ChangeDetectionError(DriftDetectionError):
    """Error during change detection."""
    pass

def handle_detection_error(error: DriftDetectionError):
    """Handle drift detection errors."""
    logger.error(
        "drift_detection_error",
        error_type=error.__class__.__name__,
        error_message=str(error)
    )
    
    # Notify administrators
    if isinstance(error, StateCollectionError):
        notify_admin("State collection failed", error)
    elif isinstance(error, ChangeDetectionError):
        notify_admin("Change detection failed", error)
```

## Best Practices

1. **State Management**
   - Keep state history for auditing
   - Implement state versioning
   - Regular state cleanup
   - Backup important states

2. **Change Detection**
   - Use appropriate comparison methods
   - Handle edge cases
   - Implement retry logic
   - Monitor detection performance

3. **Data Normalization**
   - Consistent property handling
   - Handle special cases
   - Document normalization rules
   - Test normalization logic

4. **Error Handling**
   - Implement proper error handling
   - Log all errors
   - Notify administrators
   - Implement recovery procedures

## Configuration

Update your `.env` file with these drift detection settings:

```bash
# Detection Settings
DETECTION_INTERVAL=300
MAX_CHANGES_PER_HOUR=100
ENABLE_AUTO_REMEDIATION=false

# Severity Settings
CRITICAL_CHANGE_THRESHOLD=10
HIGH_CHANGE_THRESHOLD=20
MEDIUM_CHANGE_THRESHOLD=50

# Notification Settings
ENABLE_CHANGE_NOTIFICATIONS=true
NOTIFICATION_CHANNELS=email,slack
```

## Monitoring

1. **Metrics to Track**
   - Detection rate
   - Change frequency
   - Severity distribution
   - Processing time
   - Error rate

2. **Alerts to Configure**
   - High change frequency
   - Critical changes
   - Detection failures
   - Processing delays

3. **Dashboards to Create**
   - Change overview
   - Severity distribution
   - Resource changes
   - Detection performance 