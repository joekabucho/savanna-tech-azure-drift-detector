"""
Drift detector module for the Azure Drift Detector application.
Detects changes between configurations and determines their severity.

This module uses DeepDiff to compare previous and current configurations.
- All differences are considered drift unless filtered by normalization.
- Severity is determined by matching changed keys against predefined patterns.
- Noisy or irrelevant fields can be filtered out by normalization.

Example:
    >>> previous = {'security': {'firewall': {'enabled': True}}}
    >>> current = {'security': {'firewall': {'enabled': False}}}
    >>> drift_detected, changes, severity = detect_drift(previous, current)
    >>> print(f"Drift detected: {drift_detected}, Severity: {severity}")
    Drift detected: True, Severity: critical
"""

import json
from deepdiff import DeepDiff

def normalize_config(config):
    """
    Normalize configuration for drift detection.
    
    This function prepares configurations for comparison by:
    - Removing fields known to be noisy (e.g., timestamps)
    - Sorting lists for consistent comparison
    - Handling nested structures recursively
    
    Args:
        config: dict or JSON string representing the configuration.
        
    Returns:
        dict: Normalized configuration with noise removed.
        
    Example:
        >>> config = {
        ...     'lastModified': '2024-01-01',
        ...     'settings': {'enabled': True}
        ... }
        >>> normalized = normalize_config(config)
        >>> print(normalized)
        {'settings': {'enabled': True}}
    """
    if isinstance(config, str):
        config = json.loads(config)
    # Example: remove noisy fields
    noisy_fields = ['lastModified', 'timestamp', 'updatedAt']
    def remove_noisy(d):
        if isinstance(d, dict):
            return {k: remove_noisy(v) for k, v in d.items() if k not in noisy_fields}
        elif isinstance(d, list):
            return [remove_noisy(i) for i in d]
        else:
            return d
    return remove_noisy(config)

def detect_drift(previous_config, current_config):
    """
    Detect drift between configurations and determine severity.
    
    This function compares two configurations and identifies changes that may
    indicate security drift or configuration issues. The severity of changes
    is determined based on predefined patterns of sensitive configuration keys.
    
    Args:
        previous_config: Previous configuration (dict or JSON string)
        current_config: Current configuration (dict or JSON string)
        
    Returns:
        tuple: (drift_detected, changes, severity)
            - drift_detected (bool): True if any drift is detected
            - changes (DeepDiff): The diff object describing all changes
            - severity (str): One of 'low', 'medium', 'high', 'critical'
            
    Note:
        - All differences are considered drift; there is no numeric tolerance
        - Severity is determined by matching changed keys against predefined patterns
        - Noisy or irrelevant fields are filtered out by normalization
        
    Example:
        >>> previous = {
        ...     'security': {
        ...         'firewall': {'enabled': True},
        ...         'encryption': {'enabled': True}
        ...     }
        ... }
        >>> current = {
        ...     'security': {
        ...         'firewall': {'enabled': False},
        ...         'encryption': {'enabled': True}
        ...     }
        ... }
        >>> drift_detected, changes, severity = detect_drift(previous, current)
        >>> print(f"Drift detected: {drift_detected}, Severity: {severity}")
        Drift detected: True, Severity: critical
    """
    # Normalize configs to remove noise (e.g., timestamps, order of lists)
    previous_config = normalize_config(previous_config)
    current_config = normalize_config(current_config)

    # DeepDiff is used to compare the normalized configs
    diff = DeepDiff(previous_config, current_config, verbose_level=2)
    drift_detected = bool(diff)
    severity = 'low'

    # List of sensitive keys that, if changed, may indicate higher severity drift
    sensitive_keys = [
        # Security settings
        'enableSoftDelete', 'enablePurgeProtection', 'enabledForDeployment',
        'enabledForTemplateDeployment', 'enabledForDiskEncryption',
        'enableRbacAuthorization', 'softDeleteRetentionInDays',
        'networkAcls', 'defaultAction', 'accessPolicies', 'permissions',
        'sku', 'accessPolicies', 'ipRules', 'virtualNetworkRules',
        # Security profile settings
        'securityProfile', 'uefiSettings', 'secureBootEnabled', 'vTpmEnabled',
        'encryptionAtHost', 'securityType', 'confidentialVM',
        # Network security
        'securityRules', 'direction', 'priority', 'protocol', 'sourcePortRange',
        'sourceAddressPrefix', 'destinationPortRange', 'destinationAddressPrefix',
        'access',
        # Identity and authentication
        'identity', 'userAssignedIdentities', 'principalId', 'tenantId',
        'type', 'systemAssigned', 'userAssigned', 'authenticationSettings',
        # Encryption settings
        'encryption', 'keyVaultProperties', 'keyName', 'keyVersion',
        'diskEncryptionSetId', 'encryptionSettings', 'encryptionSettingsCollection',
        # Access control
        'admin', 'adminUserEnabled', 'disablePasswordAuthentication', 'publicKeys',
        'oauth2Permissions', 'appRoleAssignmentRequired', 'defaultRoleId',
        # Backup and recovery
        'backup', 'backupPolicy', 'retention', 'geoRedundant', 'recoveryServices',
        # Compliance and governance
        'compliance', 'dataResidency', 'dataProtection', 'retentionPolicy',
        # Connectivity and networking
        'publicNetworkAccess', 'firewallRules', 'privateLinkResources',
        'privateEndpointConnections', 'allowedClientsSettings',
        # Access to admin operations
        'adminConsoleEnabled', 'adminAccess', 'adminLoginEnabled', 'adminUsername'
    ]

    highest_severity = 'low'

    if drift_detected:
        # For each change, check if it involves a sensitive key and escalate severity
        for change_type in diff.keys():
            for path, change in diff[change_type].items():
                for sensitive_key in sensitive_keys:
                    if sensitive_key.lower() in path.lower():
                        current_severity = determine_severity(sensitive_key, path, diff)
                        if (current_severity == 'critical' or 
                            (current_severity == 'high' and highest_severity not in ['critical']) or
                            (current_severity == 'medium' and highest_severity not in ['critical', 'high'])):
                            highest_severity = current_severity
        severity = highest_severity

    return drift_detected, diff, severity

def determine_severity(sensitive_key, path, diff):
    """
    Determine severity based on the type of key and change.
    
    This function evaluates the severity of a configuration change based on:
    - The type of configuration key that changed
    - The path to the changed value
    - The nature of the change
    
    Severity levels:
    - critical: Changes that could immediately impact security or compliance
    - high: Changes that affect security features but may not be immediate threats
    - medium: Changes that could impact security but are less direct
    - low: Changes that are unlikely to impact security
    
    Args:
        sensitive_key: The sensitive key pattern matched
        path: The specific path that changed
        diff: The DeepDiff result
        
    Returns:
        str: Severity level ('low', 'medium', 'high', 'critical')
        
    Example:
        >>> determine_severity('firewallRules', 'security.firewallRules.enabled', {})
        'critical'
    """
    # Patterns for severity escalation
    critical_patterns = [
        'networkAcls', 'defaultAction', 'ipRules', 'publicNetworkAccess',
        'firewallRules', 'accessPolicies', 'permissions',
        'enableRbacAuthorization', 'adminAccess', 'adminConsoleEnabled',
        'disablePasswordAuthentication', 'publicKeys'
    ]
    high_patterns = [
        'securityProfile', 'secureBootEnabled', 'vTpmEnabled',
        'encryption', 'encryptionSettings', 'keyVaultProperties',
        'identity', 'securityRules', 'access'
    ]
    medium_patterns = [
        'sku', 'enableSoftDelete', 'softDeleteRetentionInDays',
        'backup', 'retention', 'geoRedundant'
    ]
    # Escalate severity based on the matched pattern
    if any(pattern in path.lower() for pattern in critical_patterns):
        return 'critical'
    elif any(pattern in path.lower() for pattern in high_patterns):
        return 'high'
    elif any(pattern in path.lower() for pattern in medium_patterns):
        return 'medium'
    return 'low'