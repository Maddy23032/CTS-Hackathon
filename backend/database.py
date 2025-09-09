# database.py
# MongoDB configuration and connection for VulnScan GUI

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import logging
import os

logger = logging.getLogger(__name__)

class MongoDB:
    def __init__(self, connection_string: str = None):
        self.client = None
        self.db = None
        # Resolve connection string with safer production behavior (no silent localhost fallback)
        env = os.getenv("ENVIRONMENT", "").lower()
        candidate = (
            connection_string
            or os.getenv("MONGODB_URI")
            or os.getenv("MONGODB_URL")
        )
        # Only allow localhost fallback during explicit non-production (dev) mode
        if not candidate and env not in ("production", "prod"):
            candidate = "mongodb://localhost:27017"
        self.connection_string = candidate
        if not self.connection_string:
            logger.warning("MongoDB URI not provided – database features will be disabled (set MONGODB_URI).")
        
    async def connect(self):
        """Connect to MongoDB"""
        if not self.connection_string:
            return  # Skip silently; app will operate in in-memory mode
        try:
            masked = self.connection_string
            if "@" in masked:
                # Mask credentials
                parts = masked.split("@", 1)
                cred, rest = parts[0], parts[1]
                if "://" in cred:
                    scheme, creds = cred.split("://", 1)
                    cred = f"{scheme}://***:***"
                masked = cred + "@" + rest
            logger.info(f"Connecting to MongoDB at {masked}")
            self.client = AsyncIOMotorClient(self.connection_string)
            self.db = self.client["VulnScan_db"]
            await self.client.admin.command('ping')
            logger.info("Connected to MongoDB successfully")
            await self.create_indexes()
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
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
