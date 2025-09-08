#!/usr/bin/env python3
"""
Check MongoDB database details and show what exists
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_database_details():
    """Check database details and what actually exists"""
    print("🔍 MongoDB Database Details")
    print("=" * 50)
    
    try:
        # Connect to MongoDB
        client = AsyncIOMotorClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
        
        # Test the connection
        await client.admin.command('ping')
        print("✅ MongoDB Connection: SUCCESS")
        print(f"   Host: localhost:27017")
        
        # Get server info
        server_info = await client.admin.command('buildInfo')
        print(f"   MongoDB Version: {server_info.get('version', 'Unknown')}")
        
        # List all databases
        print("\n📂 Available Databases:")
        db_list = await client.list_database_names()
        for db_name in db_list:
            db = client[db_name]
            collections = await db.list_collection_names()
            collection_count = len(collections)
            print(f"   📁 {db_name} ({collection_count} collections)")
            if collections:
                for collection in collections:
                    col = db[collection]
                    doc_count = await col.count_documents({})
                    print(f"      📄 {collection}: {doc_count} documents")
        
        # Check specifically for VulnScan database
        print("\n🎯 VulnScan Database Status:")
        VulnScan_db_name = "VulnScan_db"  # This is what's configured in database.py
        
        if VulnScan_db_name in db_list:
            print(f"   ✅ Database '{VulnScan_db_name}' EXISTS")
            db = client[VulnScan_db_name]
            collections = await db.list_collection_names()
            
            if collections:
                print(f"   📊 Collections in {VulnScan_db_name}:")
                for collection in collections:
                    col = db[collection]
                    doc_count = await col.count_documents({})
                    print(f"      📄 {collection}: {doc_count} documents")
                    
                    # Show sample document if available
                    if doc_count > 0:
                        sample = await col.find_one()
                        if sample:
                            # Remove _id for cleaner display
                            if '_id' in sample:
                                del sample['_id']
                            print(f"         Sample: {str(sample)[:100]}...")
            else:
                print(f"   ℹ️  Database '{VulnScan_db_name}' exists but has no collections")
        else:
            print(f"   ℹ️  Database '{VulnScan_db_name}' does not exist yet")
            print("   📝 It will be created automatically when first scan is run")
        
        # Show configuration details
        print(f"\n⚙️  Configuration Details:")
        print(f"   📍 Database Location: MongoDB data directory")
        print(f"   📋 Database Name: {VulnScan_db_name}")
        print(f"   🔗 Connection String: mongodb://localhost:27017")
        print(f"   📁 Config File: backend/database.py")
        
        # Show expected collections
        print(f"\n📋 Expected Collections:")
        expected_collections = [
            "scans - Scan metadata and results",
            "vulnerabilities - Individual vulnerability records",
            "scan_logs - Scan execution logs", 
            "analytics - Cached analytics data"
        ]
        for collection in expected_collections:
            print(f"   • {collection}")
        
        await client.close()
        
        return True
        
    except Exception as e:
        print("❌ MongoDB Connection: FAILED")
        print(f"   Error: {e}")
        print("\n🛠️  Make sure MongoDB is running:")
        print("   1. Check if MongoDB service is started")
        print("   2. Default location: localhost:27017")
        print("   3. Data directory: e:\\mongodb-win32-x86_64-windows-8.0.13\\data")
        
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(check_database_details())
    except KeyboardInterrupt:
        print("\n⚠️  Check interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
