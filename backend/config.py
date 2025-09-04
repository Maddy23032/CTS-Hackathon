# MongoDB Configuration for VulnPy
# This file contains the MongoDB configuration and connection settings

# MongoDB Connection Settings
MONGODB_URL = "mongodb://localhost:27017"
DATABASE_NAME = "vulnpy_database"

# Collection Names
SCANS_COLLECTION = "scans"
VULNERABILITIES_COLLECTION = "vulnerabilities"
SCAN_LOGS_COLLECTION = "scan_logs"
ANALYTICS_COLLECTION = "analytics"

# Index Configurations
# These indexes will be created automatically when the database connects
INDEXES = {
    "scans": [
        [("scan_id", 1)],  # Unique index on scan_id
        [("target_url", 1)],  # Index for filtering by target URL
        [("status", 1)],  # Index for filtering by status
        [("created_at", -1)],  # Index for sorting by creation date (descending)
        [("scan_types", 1)],  # Index for filtering by scan types
    ],
    "vulnerabilities": [
        [("scan_id", 1)],  # Index for finding vulnerabilities by scan
        [("type", 1)],  # Index for filtering by vulnerability type
        [("severity", 1)],  # Index for filtering by severity
        [("url", 1)],  # Index for searching by URL
        [("created_at", -1)],  # Index for sorting by creation date
        [("scan_id", 1), ("type", 1)],  # Compound index for scan + type queries
        [("severity", 1), ("type", 1)],  # Compound index for severity + type queries
    ],
    "scan_logs": [
        [("scan_id", 1)],  # Index for finding logs by scan
        [("timestamp", -1)],  # Index for sorting by timestamp
        [("level", 1)],  # Index for filtering by log level
        [("scan_id", 1), ("timestamp", -1)],  # Compound index for scan + timestamp
    ],
    "analytics": [
        [("date", 1)],  # Unique index on date
    ]
}

# MongoDB Settings
MONGODB_SETTINGS = {
    "serverSelectionTimeoutMS": 5000,  # 5 second timeout for server selection
    "connectTimeoutMS": 10000,  # 10 second connection timeout
    "socketTimeoutMS": 30000,  # 30 second socket timeout
    "maxPoolSize": 50,  # Maximum number of connections in the pool
    "minPoolSize": 5,  # Minimum number of connections in the pool
    "maxIdleTimeMS": 300000,  # Maximum time a connection can be idle (5 minutes)
    "retryWrites": True,  # Enable retryable writes
    "w": "majority",  # Write concern - wait for majority of replica set members
    "j": True,  # Wait for journal commit
}

# Analytics Settings
ANALYTICS_SETTINGS = {
    "auto_update": True,  # Automatically update daily analytics
    "update_hour": 1,  # Hour to update analytics (1 AM)
    "retention_days": 365,  # How long to keep daily analytics data
}

# Performance Settings
PERFORMANCE_SETTINGS = {
    "batch_size": 1000,  # Batch size for bulk operations
    "max_scan_logs": 10000,  # Maximum logs to keep per scan
    "compression": "zstd",  # MongoDB compression algorithm
}

# Security Settings (for production)
SECURITY_SETTINGS = {
    "auth_source": "admin",  # Authentication database
    "ssl": False,  # Enable SSL/TLS (set to True in production)
    "ssl_cert_reqs": "CERT_NONE",  # SSL certificate requirements
    "ssl_ca_certs": None,  # Path to CA certificates
    "ssl_certfile": None,  # Path to client certificate
    "ssl_keyfile": None,  # Path to client private key
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/mongodb.log",
    "max_size": "10MB",
    "backup_count": 5,
}

# Development vs Production Settings
import os

if os.getenv("ENVIRONMENT") == "production":
    # Production settings
    MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    SECURITY_SETTINGS["ssl"] = True
    SECURITY_SETTINGS["ssl_cert_reqs"] = "CERT_REQUIRED"
    MONGODB_SETTINGS["w"] = "majority"
    MONGODB_SETTINGS["j"] = True
else:
    # Development settings
    MONGODB_URL = "mongodb://localhost:27017"
    SECURITY_SETTINGS["ssl"] = False
    MONGODB_SETTINGS["w"] = 1
    MONGODB_SETTINGS["j"] = False

# Database Migration Settings
MIGRATION_SETTINGS = {
    "version": "1.0.0",
    "auto_migrate": True,
    "backup_before_migration": True,
}

# Feature Flags
FEATURE_FLAGS = {
    "enable_analytics": True,
    "enable_ai_enrichment": True,
    "enable_real_time_updates": True,
    "enable_vulnerability_deduplication": True,
    "enable_scan_scheduling": False,  # Future feature
    "enable_user_management": False,  # Future feature
}

# Data Validation Settings
VALIDATION_SETTINGS = {
    "strict_mode": False,  # Strict validation of data models
    "max_url_length": 2048,
    "max_parameter_length": 256,
    "max_payload_length": 4096,
    "max_evidence_length": 8192,
    "max_log_message_length": 1024,
}

# Cache Settings (for future Redis integration)
CACHE_SETTINGS = {
    "enabled": False,
    "redis_url": "redis://localhost:6379",
    "default_timeout": 300,  # 5 minutes
    "scan_cache_timeout": 3600,  # 1 hour
    "analytics_cache_timeout": 1800,  # 30 minutes
}

# Export all settings
__all__ = [
    "MONGODB_URL",
    "DATABASE_NAME",
    "SCANS_COLLECTION",
    "VULNERABILITIES_COLLECTION", 
    "SCAN_LOGS_COLLECTION",
    "ANALYTICS_COLLECTION",
    "INDEXES",
    "MONGODB_SETTINGS",
    "ANALYTICS_SETTINGS",
    "PERFORMANCE_SETTINGS",
    "SECURITY_SETTINGS",
    "LOGGING_CONFIG",
    "MIGRATION_SETTINGS",
    "FEATURE_FLAGS",
    "VALIDATION_SETTINGS",
    "CACHE_SETTINGS",
]
