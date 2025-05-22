"""
MongoDB configuration for the Azure Drift Detector application.

This module handles MongoDB connection and configuration,
including indexes for optimal query performance.
"""

import os
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
import logging

logger = logging.getLogger(__name__)

# MongoDB connection settings
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
MONGODB_DB = os.environ.get('MONGODB_DB', 'azure_drift_detector')

# Initialize MongoDB client
client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB]

def init_mongodb():
    """
    Initialize MongoDB connection and create indexes.
    """
    try:
        # Test connection
        client.admin.command('ping')
        logger.info("Successfully connected to MongoDB")
        
        # Create indexes for configurations collection
        db.configurations.create_index([
            ('resource_id', ASCENDING),
            ('resource_type', ASCENDING),
            ('timestamp', DESCENDING)
        ])
        
        # Create index for drift history
        db.drift_history.create_index([
            ('resource_id', ASCENDING),
            ('detected_at', DESCENDING)
        ])
        
        # Create index for sign-in logs
        db.signin_logs.create_index([
            ('timestamp', DESCENDING)
        ])
        
        # Create TTL index for configurations (keep last 30 days)
        db.configurations.create_index(
            'timestamp',
            expireAfterSeconds=30 * 24 * 60 * 60  # 30 days
        )
        
        # Create TTL index for sign-in logs (keep last 90 days)
        db.signin_logs.create_index(
            'timestamp',
            expireAfterSeconds=90 * 24 * 60 * 60  # 90 days
        )
        
        logger.info("MongoDB indexes created successfully")
        
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise

def get_collection(collection_name):
    """
    Get a MongoDB collection with proper error handling.
    
    Args:
        collection_name (str): Name of the collection to get
        
    Returns:
        Collection: MongoDB collection object
    """
    try:
        return db[collection_name]
    except Exception as e:
        logger.error(f"Error accessing collection {collection_name}: {str(e)}")
        raise 