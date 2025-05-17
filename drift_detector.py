"""
Drift detector module for the Azure Drift Detector application.
Detects changes between configurations and determines their severity.
"""

import json
from deepdiff import DeepDiff


def detect_drift(previous_config, current_config):
    """
    Detect drift between configurations and determine severity
    
    Args:
        previous_config: Previous configuration (dict or JSON string)
        current_config: Current configuration (dict or JSON string)
        
    Returns:
        tuple: (drift_detected, changes, severity)
    """
    if isinstance(previous_config, str):
        previous_config = json.loads(previous_config)
    if isinstance(current_config, str):
        current_config = json.loads(current_config)
        
    diff = DeepDiff(previous_config, current_config, verbose_level=2)
    drift_detected = bool(diff)
    severity = 'low'
    
    if drift_detected:
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
    Determine severity based on the type of key and change
    
    Args:
        sensitive_key: The sensitive key pattern matched
        path: The specific path that changed
        diff: The DeepDiff result
        
    Returns:
        str: Severity level ('low', 'medium', 'high', 'critical')
    """
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
    
    if any(pattern in path.lower() for pattern in critical_patterns):
        return 'critical'
    elif any(pattern in path.lower() for pattern in high_patterns):
        return 'high'
    elif any(pattern in path.lower() for pattern in medium_patterns):
        return 'medium'
    return 'low'