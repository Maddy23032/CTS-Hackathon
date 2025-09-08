#!/usr/bin/env python3
"""
Check MongoDB connection status and provide setup guidance
"""

import sys
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_mongodb_status():
    """Check if MongoDB is running and accessible"""
    print("🔍 Checking MongoDB Status...")
    print("=" * 40)
    
    try:
        # Try to connect to MongoDB
        client = AsyncIOMotorClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
        
        # Test the connection
        await client.admin.command('ping')
        
        # Get server info
        server_info = await client.admin.command('buildInfo')
        
        print("✅ MongoDB is running!")
        print(f"   Version: {server_info.get('version', 'Unknown')}")
        print(f"   Host: localhost:27017")
        
        # Check if our database exists
        db_list = await client.list_database_names()
        if 'VulnScan' in db_list:
            print("✅ VulnScan database exists")
            
            # Check collections
            db = client.VulnScan
            collections = await db.list_collection_names()
            if collections:
                print(f"✅ Collections found: {', '.join(collections)}")
            else:
                print("ℹ️  No collections yet (will be created on first use)")
        else:
            print("ℹ️  VulnScan database will be created on first use")
        
        await client.close()
        
        print("\n🎉 MongoDB is ready for VulnScan integration!")
        return True
        
    except Exception as e:
        print("❌ MongoDB is not accessible")
        print(f"   Error: {e}")
        print("\n🛠️  Setup Instructions:")
        print("   1. Install MongoDB Community Server:")
        print("      https://www.mongodb.com/try/download/community")
        print("   2. Start MongoDB service:")
        print("      Windows: Services → MongoDB Server → Start")
        print("   3. Or use Docker:")
        print("      docker run --name mongodb -p 27017:27017 -d mongo:latest")
        print("   4. Or use MongoDB Atlas (cloud):")
        print("      https://www.mongodb.com/atlas")
        
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(check_mongodb_status())
        if success:
            print("\n➡️  Next: Run the full integration test:")
            print("   python test_mongodb_integration.py")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Check interrupted by user")
        sys.exit(1)
