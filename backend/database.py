# database.py
# MongoDB configuration and connection for VulnScan GUI

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class MongoDB:
    def __init__(self, connection_string: str = "mongodb://localhost:27017"):
        self.client = None
        self.db = None
        self.connection_string = connection_string
        
    async def connect(self):
        """Connect to MongoDB"""
        try:
            self.client = AsyncIOMotorClient(self.connection_string)
            self.db = self.client["VulnScan_db"]
            
            # Test connection
            await self.client.admin.command('ping')
            logger.info("Connected to MongoDB successfully")
            
            # Create indexes for better performance
            await self.create_indexes()
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            # Don't raise the exception, just log it
            self.client = None
            self.db = None
            
    def is_connected(self) -> bool:
        """Check if MongoDB is connected"""
        return self.client is not None and self.db is not None
    
    async def create_indexes(self):
        """Create database indexes for optimal performance"""
        try:
            # Scans collection indexes
            await self.db.scans.create_index([("target_url", ASCENDING)])
            await self.db.scans.create_index([("start_time", DESCENDING)])
            await self.db.scans.create_index([("status", ASCENDING)])
            await self.db.scans.create_index([("scan_types", ASCENDING)])
            
            # Vulnerabilities collection indexes
            await self.db.vulnerabilities.create_index([("scan_id", ASCENDING)])
            await self.db.vulnerabilities.create_index([("type", ASCENDING)])
            await self.db.vulnerabilities.create_index([("severity", ASCENDING)])
            await self.db.vulnerabilities.create_index([("created_at", DESCENDING)])
            
            # Compound indexes for common queries
            await self.db.vulnerabilities.create_index([
                ("scan_id", ASCENDING), 
                ("type", ASCENDING)
            ])
            
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.warning(f"Failed to create indexes: {e}")
    
    async def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")

# Global MongoDB instance
mongodb = MongoDB()

# Database collections shortcuts
async def get_scans_collection():
    return mongodb.db.scans

async def get_vulnerabilities_collection():
    return mongodb.db.vulnerabilities

async def get_scan_logs_collection():
    return mongodb.db.scan_logs

async def get_analytics_collection():
    return mongodb.db.analytics
