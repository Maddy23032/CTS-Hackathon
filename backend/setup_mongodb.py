#!/usr/bin/env python3
"""
MongoDB Setup and Application Startup Script for VulnScan GUI
This script handles MongoDB setup, data migration, and application startup
"""

import os
import sys
import asyncio
import logging
import subprocess
import time
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from database import mongodb
from mongo_service import mongo_service
import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_mongodb_running():
    """Check if MongoDB is running"""
    try:
        import pymongo
        client = pymongo.MongoClient(config.MONGODB_URL, serverSelectionTimeoutMS=2000)
        client.server_info()
        client.close()
        return True
    except Exception:
        return False

def start_mongodb():
    """Start MongoDB service"""
    system = os.name
    
    try:
        if system == 'nt':  # Windows
            logger.info("Starting MongoDB on Windows...")
            # Try to start MongoDB service
            result = subprocess.run(
                ['net', 'start', 'MongoDB'],
                capture_output=True,
                text=True,
                shell=True
            )
            if result.returncode != 0:
                logger.warning("Failed to start MongoDB service, trying mongod command...")
                # Try to start mongod directly
                subprocess.Popen([
                    'mongod',
                    '--dbpath', 'C:\\data\\db',
                    '--port', '27017'
                ], shell=True)
        else:  # Linux/Mac
            logger.info("Starting MongoDB on Unix-like system...")
            # Try to start MongoDB service
            result = subprocess.run(
                ['sudo', 'systemctl', 'start', 'mongod'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logger.warning("Failed to start MongoDB service, trying mongod command...")
                # Try to start mongod directly
                subprocess.Popen([
                    'mongod',
                    '--dbpath', '/data/db',
                    '--port', '27017'
                ])
        
        # Wait for MongoDB to start
        for i in range(30):  # Wait up to 30 seconds
            if check_mongodb_running():
                logger.info("MongoDB is running!")
                return True
            time.sleep(1)
            
        return False
        
    except Exception as e:
        logger.error(f"Failed to start MongoDB: {e}")
        return False

async def setup_database():
    """Set up database connections and indexes"""
    try:
        logger.info("Connecting to MongoDB...")
        await mongodb.connect()
        
        logger.info("Setting up database indexes...")
        # Indexes are automatically created in the connect method
        
        logger.info("Testing database connection...")
        # Test the connection by creating a simple query
        scans_collection = mongodb.db.scans
        await scans_collection.find_one()
        
        logger.info("Database setup completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Database setup failed: {e}")
        return False

async def create_sample_data():
    """Create sample data for testing (optional)"""
    try:
        from models import ScanDocument, VulnerabilityDocument, ScanStatus, VulnerabilityType, SeverityLevel
        from datetime import datetime
        import uuid
        
        logger.info("Creating sample data...")
        
        # Check if we already have data
        scans_collection = mongodb.db.scans
        existing_scans = await scans_collection.count_documents({})
        
        if existing_scans > 0:
            logger.info(f"Found {existing_scans} existing scans, skipping sample data creation")
            return
        
        # Create sample scan
        sample_scan = ScanDocument(
            scan_id=str(uuid.uuid4()),
            target_url="https://example.com",
            scan_types=["xss", "sqli"],
            mode="fast",
            status=ScanStatus.COMPLETED,
            config={
                "headless": True,
                "ai_calls": 10,
                "max_depth": 2
            },
            vulnerabilities_found=2,
            total_time=45.5
        )
        
        await mongo_service.create_scan(sample_scan)
        
        # Create sample vulnerabilities
        sample_vulns = [
            VulnerabilityDocument(
                scan_id=sample_scan.scan_id,
                url="https://example.com/search",
                parameter="q",
                payload="<script>alert('xss')</script>",
                evidence="Alert box appeared",
                type=VulnerabilityType.XSS,
                severity=SeverityLevel.HIGH,
                confidence="High",
                remediation="Sanitize user input",
                cvss_score=7.5,
                epss_score=0.023
            ),
            VulnerabilityDocument(
                scan_id=sample_scan.scan_id,
                url="https://example.com/login",
                parameter="username",
                payload="admin' OR '1'='1' --",
                evidence="SQL error in response",
                type=VulnerabilityType.SQLI,
                severity=SeverityLevel.CRITICAL,
                confidence="High",
                remediation="Use parameterized queries",
                cvss_score=9.1,
                epss_score=0.045
            )
        ]
        
        for vuln in sample_vulns:
            await mongo_service.create_vulnerability(vuln)
        
        # Update analytics
        await mongo_service.update_analytics()
        
        logger.info("Sample data created successfully!")
        
    except Exception as e:
        logger.error(f"Failed to create sample data: {e}")

def start_backend():
    """Start the FastAPI backend server"""
    try:
        logger.info("Starting FastAPI backend server...")
        import uvicorn
        uvicorn.run(
            "api_server:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            log_level="info"
        )
    except Exception as e:
        logger.error(f"Failed to start backend server: {e}")
        return False

def start_frontend():
    """Start the React frontend development server"""
    try:
        logger.info("Starting React frontend server...")
        frontend_dir = backend_dir.parent / "frontend"
        
        if not frontend_dir.exists():
            logger.warning("Frontend directory not found, skipping frontend startup")
            return False
        
        # Check if npm is available
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning("npm not found, skipping frontend startup")
            return False
        
        # Install dependencies if needed
        if not (frontend_dir / "node_modules").exists():
            logger.info("Installing frontend dependencies...")
            subprocess.run(['npm', 'install'], cwd=frontend_dir, check=True)
        
        # Start the development server
        subprocess.Popen(['npm', 'start'], cwd=frontend_dir)
        logger.info("Frontend server starting at http://localhost:3000")
        return True
        
    except Exception as e:
        logger.error(f"Failed to start frontend server: {e}")
        return False

async def main():
    """Main setup and startup function"""
    logger.info("=" * 60)
    logger.info("VulnScan GUI - MongoDB Setup and Application Startup")
    logger.info("=" * 60)
    
    # Step 1: Check/Start MongoDB
    if not check_mongodb_running():
        logger.info("MongoDB is not running, attempting to start it...")
        if not start_mongodb():
            logger.error("Failed to start MongoDB. Please start it manually and try again.")
            logger.error("Installation instructions:")
            logger.error("  Windows: https://docs.mongodb.com/manual/installation/install-mongodb-on-windows/")
            logger.error("  macOS: https://docs.mongodb.com/manual/installation/install-mongodb-on-os-x/")
            logger.error("  Linux: https://docs.mongodb.com/manual/installation/install-mongodb-on-linux/")
            return False
    else:
        logger.info("MongoDB is already running!")
    
    # Step 2: Set up database
    if not await setup_database():
        logger.error("Database setup failed!")
        return False
    
    # Step 3: Create sample data (optional)
    create_sample = input("Would you like to create sample data for testing? (y/N): ").lower().strip()
    if create_sample in ['y', 'yes']:
        await create_sample_data()
    
    # Step 4: Show connection info
    logger.info("=" * 60)
    logger.info("Setup completed successfully!")
    logger.info(f"MongoDB URL: {config.MONGODB_URL}")
    logger.info(f"Database: {config.DATABASE_NAME}")
    logger.info("=" * 60)
    
    # Step 5: Start servers
    start_servers = input("Would you like to start the application servers now? (Y/n): ").lower().strip()
    if start_servers not in ['n', 'no']:
        
        # Start frontend in background
        start_frontend()
        
        # Start backend (this will block)
        logger.info("Starting backend server (this will block)...")
        logger.info("API will be available at: http://localhost:8000")
        logger.info("API docs will be available at: http://localhost:8000/docs")
        logger.info("Press Ctrl+C to stop the server")
        
        start_backend()
    
    # Cleanup
    await mongodb.disconnect()
    return True

def print_usage():
    """Print usage information"""
    print("VulnScan GUI MongoDB Setup Script")
    print("Usage: python setup_mongodb.py [options]")
    print("")
    print("Options:")
    print("  --help, -h          Show this help message")
    print("  --check-mongo       Check if MongoDB is running")
    print("  --setup-only        Only setup database, don't start servers")
    print("  --create-sample     Create sample data")
    print("  --start-backend     Start only the backend server")
    print("  --start-frontend    Start only the frontend server")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] in ['--help', '-h']:
            print_usage()
            sys.exit(0)
        elif sys.argv[1] == '--check-mongo':
            if check_mongodb_running():
                print("✓ MongoDB is running")
                sys.exit(0)
            else:
                print("✗ MongoDB is not running")
                sys.exit(1)
        elif sys.argv[1] == '--setup-only':
            asyncio.run(setup_database())
            sys.exit(0)
        elif sys.argv[1] == '--create-sample':
            async def create_sample_only():
                await mongodb.connect()
                await create_sample_data()
                await mongodb.disconnect()
            asyncio.run(create_sample_only())
            sys.exit(0)
        elif sys.argv[1] == '--start-backend':
            start_backend()
            sys.exit(0)
        elif sys.argv[1] == '--start-frontend':
            start_frontend()
            sys.exit(0)
    
    # Run main setup
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user")
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        sys.exit(1)
