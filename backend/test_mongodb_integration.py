#!/usr/bin/env python3
"""
Test script to verify MongoDB integration is working correctly
"""

import sys
import os
import asyncio
import json
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

async def test_mongodb_integration():
    """Test the MongoDB integration components"""
    print("🧪 Testing MongoDB Integration...")
    print("=" * 50)
    
    try:
        # Test 1: Import all MongoDB components
        print("1. Testing imports...")
        from database import mongodb
        from mongo_service import mongo_service
        from models import ScanDocument, VulnerabilityDocument, ScanStatus, VulnerabilityType, SeverityLevel
        print("   ✅ All imports successful")
        
        # Test 2: Test database connection
        print("2. Testing database connection...")
        await mongodb.connect()
        print("   ✅ Database connection successful")
        
        # Test 3: Test basic database operations
        print("3. Testing basic operations...")
        
        # Create a test scan
        from datetime import datetime
        import uuid
        
        test_scan = ScanDocument(
            scan_id=str(uuid.uuid4()),
            target_url="https://test.example.com",
            scan_types=["xss"],
            mode="fast",
            status=ScanStatus.COMPLETED,
            config={"test": True},
            vulnerabilities_found=1,
            total_time=30.5
        )
        
        scan_id = await mongo_service.create_scan(test_scan)
        print(f"   ✅ Created test scan: {scan_id}")
        
        # Create a test vulnerability
        test_vuln = VulnerabilityDocument(
            scan_id=scan_id,
            url="https://test.example.com/test",
            parameter="test",
            payload="<script>alert('test')</script>",
            evidence="Test evidence",
            type=VulnerabilityType.XSS,
            severity=SeverityLevel.MEDIUM,
            confidence="High",
            cvss_score=5.0,
            epss_score=0.1
        )
        
        vuln_id = await mongo_service.create_vulnerability(test_vuln)
        print(f"   ✅ Created test vulnerability: {vuln_id}")
        
        # Test 4: Test queries
        print("4. Testing queries...")
        
        # Get scan history
        history = await mongo_service.get_scan_history(page=1, per_page=10)
        print(f"   ✅ Retrieved scan history: {len(history['scans'])} scans")
        
        # Search vulnerabilities
        vulns = await mongo_service.get_vulnerabilities(scan_id=scan_id)
        print(f"   ✅ Retrieved vulnerabilities: {len(vulns['vulnerabilities'])} found")
        
        # Test 5: Test analytics
        print("5. Testing analytics...")
        await mongo_service.update_analytics()
        analytics = await mongo_service.get_analytics(days=7)
        print(f"   ✅ Analytics updated and retrieved: {analytics.get('total_scans', 0)} total scans")
        
        # Test 6: Clean up test data
        print("6. Cleaning up test data...")
        # Note: In a real application, you'd want to delete test data
        # For now, we'll leave it as sample data
        print("   ✅ Test data left as sample data")
        
        # Close connection
        await mongodb.close()
        print("   ✅ Database connection closed")
        
        print("\n🎉 All tests passed! MongoDB integration is working correctly.")
        print("\nNext steps:")
        print("- Start the backend server: python api_server.py")
        print("- Test the new endpoints:")
        print("  • GET /api/scan/history")
        print("  • GET /api/vulnerabilities/search") 
        print("  • GET /api/analytics")
        print("- Use the new React components:")
        print("  • ScanHistory")
        print("  • VulnerabilitySearch")
        print("  • Analytics")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        print("   Please make sure all MongoDB dependencies are installed:")
        print("   pip install motor pymongo")
        return False
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        print("   Please check that MongoDB is running and accessible")
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(test_mongodb_integration())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)
