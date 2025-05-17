"""
Tests for the drift detection functionality in the Azure Drift Detector application.
"""

import pytest
import json
from deepdiff import DeepDiff

from drift_detector import detect_drift, determine_severity


def test_detect_drift_no_changes():
    """Test drift detection with identical configurations."""
    config1 = {
        "name": "test-vm",
        "size": "Standard_D2s_v3",
        "location": "eastus",
        "properties": {
            "hardwareProfile": {"vmSize": "Standard_D2s_v3"},
            "storageProfile": {
                "osDisk": {"osType": "Linux", "createOption": "FromImage"},
                "imageReference": {
                    "publisher": "Canonical",
                    "offer": "UbuntuServer",
                    "sku": "18.04-LTS"
                }
            }
        }
    }
    
    config2 = {
        "name": "test-vm",
        "size": "Standard_D2s_v3",
        "location": "eastus",
        "properties": {
            "hardwareProfile": {"vmSize": "Standard_D2s_v3"},
            "storageProfile": {
                "osDisk": {"osType": "Linux", "createOption": "FromImage"},
                "imageReference": {
                    "publisher": "Canonical",
                    "offer": "UbuntuServer",
                    "sku": "18.04-LTS"
                }
            }
        }
    }
    
    drift_detected, changes, severity = detect_drift(config1, config2)
    
    assert not drift_detected
    assert changes == {} 
    assert severity == 'low'  


def test_detect_drift_minor_changes():
    """Test drift detection with minor configuration changes."""
    config1 = {
        "name": "test-vm",
        "size": "Standard_D2s_v3",
        "location": "eastus",
        "tags": {"environment": "dev"}
    }
    
    config2 = {
        "name": "test-vm",
        "size": "Standard_D2s_v3",
        "location": "eastus",
        "tags": {"environment": "test"} 
    }
    
    drift_detected, changes, severity = detect_drift(config1, config2)
    
    assert drift_detected
    assert "values_changed" in changes
    assert severity == 'low' 


def test_detect_drift_major_changes():
    """Test drift detection with major configuration changes."""
    config1 = {
        "name": "test-vm",
        "size": "Standard_D2s_v3", 
        "location": "eastus",
        "properties": {
            "networkProfile": {
                "networkInterfaces": [
                    {"id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.Network/networkInterfaces/test-nic"}
                ]
            },
            "securityProfile": {
                "securityType": "TrustedLaunch",
                "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}
            }
        }
    }
    
    config2 = {
        "name": "test-vm",
        "size": "Standard_D8s_v3",  
        "location": "eastus",
        "properties": {
            "networkProfile": {
                "networkInterfaces": [
                    {"id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.Network/networkInterfaces/test-nic"}
                ]
            },
            "securityProfile": {
                "securityType": "TrustedLaunch",
                "uefiSettings": {"secureBootEnabled": False, "vTpmEnabled": True} 
            }
        }
    }
    
    drift_detected, changes, severity = detect_drift(config1, config2)
    
    assert drift_detected
    assert "values_changed" in changes
    assert severity == 'high' 


def test_detect_drift_critical_changes():
    """Test drift detection with critical security-related changes."""
    config1 = {
        "name": "test-keyvault",
        "properties": {
            "enableRbacAuthorization": True,
            "enableSoftDelete": True,
            "softDeleteRetentionInDays": 90,
            "accessPolicies": [
                {
                    "objectId": "object-id-1",
                    "permissions": {
                        "keys": ["Get", "List"],
                        "secrets": ["Get", "List"],
                        "certificates": ["Get", "List"]
                    }
                }
            ],
            "networkAcls": {
                "defaultAction": "Deny",
                "ipRules": [{"value": "1.2.3.4/32"}]
            }
        }
    }
    
    config2 = {
        "name": "test-keyvault",
        "properties": {
            "enableRbacAuthorization": False, 
            "enableSoftDelete": False, 
            "accessPolicies": [
                {
                    "objectId": "object-id-1",
                    "permissions": {
                        "keys": ["Get", "List", "Create", "Delete"], 
                        "secrets": ["Get", "List", "Set", "Delete"], 
                        "certificates": ["Get", "List", "Create", "Delete"]  
                    }
                }
            ],
            "networkAcls": {
                "defaultAction": "Allow",
                "ipRules": [] 
            }
        }
    }
    
    drift_detected, changes, severity = detect_drift(config1, config2)
    
    assert drift_detected
    assert "values_changed" in changes or "dictionary_item_removed" in changes
    assert severity == 'critical' 


def test_determine_severity_key_based():
    """Test severity determination based on specific key changes."""
    security_path = "root['properties']['securityProfile']['uefiSettings']['secureBootEnabled']"
    diff_result = {"values_changed": {security_path: {"old_value": True, "new_value": False}}}
    severity = determine_severity("secureBootEnabled", security_path, diff_result)
    assert severity == 'high'
    
    network_path = "root['properties']['networkAcls']['defaultAction']"
    diff_result = {"values_changed": {network_path: {"old_value": "Deny", "new_value": "Allow"}}}
    severity = determine_severity("defaultAction", network_path, diff_result)
    assert severity == 'critical'
    
    tag_path = "root['tags']['owner']"
    diff_result = {"values_changed": {tag_path: {"old_value": "TeamA", "new_value": "TeamB"}}}
    severity = determine_severity("owner", tag_path, diff_result)
    assert severity == 'low'