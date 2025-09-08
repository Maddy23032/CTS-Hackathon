# mongo_service.py
# Service layer for MongoDB operations

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from models import (
    ScanDocument, VulnerabilityDocument, ScanLogEntry, AnalyticsDocument,
    ScanStatus, VulnerabilityType, SeverityLevel
)
from database import mongodb
import logging

logger = logging.getLogger(__name__)

class MongoService:
    
    def _check_connection(self):
        """Check if MongoDB is available"""
        if not mongodb.is_connected():
            logger.warning("MongoDB not available - operation skipped")
            return False
        return True
    
    # ==================== SCAN OPERATIONS ====================
    
    async def create_scan(self, scan_data: ScanDocument) -> str:
        """Create a new scan in the database"""
        if not self._check_connection():
            return scan_data.scan_id
            
        try:
            scans_collection = mongodb.db.scans
            result = await scans_collection.insert_one(scan_data.dict())
            logger.info(f"Created scan {scan_data.scan_id}")
            return scan_data.scan_id
        except Exception as e:
            logger.error(f"Failed to create scan: {e}")
            return scan_data.scan_id  # Return ID even if storage fails
    
    async def update_scan(self, scan_id: str, update_data: Dict[str, Any]) -> bool:
        """Update scan with new data"""
        if not self._check_connection():
            return True  # Pretend success
            
        try:
            scans_collection = mongodb.db.scans
            update_data["updated_at"] = datetime.utcnow()
            result = await scans_collection.update_one(
                {"scan_id": scan_id},
                {"$set": update_data}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update scan {scan_id}: {e}")
            return False
    
    async def get_scan(self, scan_id: str) -> Optional[ScanDocument]:
        """Get a specific scan by ID"""
        if not self._check_connection():
            return None
            
        try:
            scans_collection = mongodb.db.scans
            scan_data = await scans_collection.find_one({"scan_id": scan_id})
            if scan_data:
                return ScanDocument(**scan_data)
            return None
        except Exception as e:
            logger.error(f"Failed to get scan {scan_id}: {e}")
            return None
    
    async def get_scan_history(
        self, 
        page: int = 1, 
        per_page: int = 20,
        status: Optional[str] = None,
        target_url: Optional[str] = None,
        scan_type: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get scan history with filtering and pagination"""
        if not self._check_connection():
            return {"scans": [], "total": 0, "page": page, "per_page": per_page}
            
        try:
            scans_collection = mongodb.db.scans
            
            # Build filter query
            filter_query = {}
            if status:
                filter_query["status"] = status
            if target_url:
                filter_query["target_url"] = {"$regex": target_url, "$options": "i"}
            if scan_type:
                filter_query["scan_types"] = {"$in": [scan_type]}
            if date_from or date_to:
                date_filter = {}
                if date_from:
                    date_filter["$gte"] = date_from
                if date_to:
                    date_filter["$lte"] = date_to
                filter_query["created_at"] = date_filter
            
            # Get total count
            total = await scans_collection.count_documents(filter_query)
            
            # Get paginated results
            skip = (page - 1) * per_page
            cursor = scans_collection.find(filter_query).sort("created_at", -1).skip(skip).limit(per_page)
            scans = await cursor.to_list(length=per_page)
            
            return {
                "scans": [ScanDocument(**scan) for scan in scans],
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page
            }
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return {"scans": [], "total": 0, "page": page, "per_page": per_page}
    
    # ==================== VULNERABILITY OPERATIONS ====================
    
    async def create_vulnerability(self, vuln_data: VulnerabilityDocument) -> str:
        """Create a new vulnerability"""
        if not self._check_connection():
            return "mock_id"
            
        try:
            vulns_collection = mongodb.db.vulnerabilities
            result = await vulns_collection.insert_one(vuln_data.dict())
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to create vulnerability: {e}")
            return "error_id"
    
    async def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        vuln_type: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        per_page: int = 50
    ) -> Dict[str, Any]:
        """Get vulnerabilities with filtering"""
        try:
            vulns_collection = mongodb.db.vulnerabilities
            
            # Build filter query
            filter_query = {}
            if scan_id:
                filter_query["scan_id"] = scan_id
            if vuln_type:
                filter_query["type"] = vuln_type
            if severity:
                filter_query["severity"] = severity
            
            # Get total count
            total = await vulns_collection.count_documents(filter_query)
            
            # Get paginated results
            skip = (page - 1) * per_page
            cursor = vulns_collection.find(filter_query).sort("created_at", -1).skip(skip).limit(per_page)
            vulns = await cursor.to_list(length=per_page)
            
            # Calculate stats
            by_type = {}
            by_severity = {}
            for vuln in vulns:
                vuln_type = vuln.get("type", "unknown")
                vuln_severity = vuln.get("severity", "unknown")
                by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
                by_severity[vuln_severity] = by_severity.get(vuln_severity, 0) + 1
            
            return {
                "vulnerabilities": [VulnerabilityDocument(**vuln) for vuln in vulns],
                "total": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "page": page,
                "per_page": per_page
            }
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return {"vulnerabilities": [], "total": 0, "by_type": {}, "by_severity": {}}
    
    # ==================== LOGGING OPERATIONS ====================
    
    async def add_scan_log(self, log_entry: ScanLogEntry):
        """Add a log entry for a scan"""
        try:
            logs_collection = mongodb.db.scan_logs
            await logs_collection.insert_one(log_entry.dict())
        except Exception as e:
            logger.error(f"Failed to add scan log: {e}")
    
    async def get_scan_logs(self, scan_id: str, level: Optional[str] = None) -> List[ScanLogEntry]:
        """Get logs for a specific scan"""
        try:
            logs_collection = mongodb.db.scan_logs
            filter_query = {"scan_id": scan_id}
            if level:
                filter_query["level"] = level
            
            cursor = logs_collection.find(filter_query).sort("timestamp", 1)
            logs = await cursor.to_list(length=1000)
            return [ScanLogEntry(**log) for log in logs]
        except Exception as e:
            logger.error(f"Failed to get scan logs: {e}")
            return []
    
    # ==================== ANALYTICS OPERATIONS ====================
    
    async def update_analytics(self, date: str = None):
        """Update analytics for a given date (default: today)"""
        if not date:
            date = datetime.utcnow().strftime("%Y-%m-%d")
        
        try:
            scans_collection = mongodb.db.scans
            vulns_collection = mongodb.db.vulnerabilities
            analytics_collection = mongodb.db.analytics
            
            # Date range for the day
            start_date = datetime.fromisoformat(f"{date}T00:00:00")
            end_date = datetime.fromisoformat(f"{date}T23:59:59")
            
            # Aggregate scan stats
            scan_stats = await scans_collection.aggregate([
                {"$match": {"created_at": {"$gte": start_date, "$lte": end_date}}},
                {"$group": {
                    "_id": None,
                    "total_scans": {"$sum": 1},
                    "completed_scans": {"$sum": {"$cond": [{"$eq": ["$status", "completed"]}, 1, 0]}},
                    "failed_scans": {"$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}},
                    "avg_scan_time": {"$avg": "$total_time"}
                }}
            ]).to_list(1)
            
            # Aggregate vulnerability stats
            vuln_stats = await vulns_collection.aggregate([
                {"$match": {"created_at": {"$gte": start_date, "$lte": end_date}}},
                {"$group": {
                    "_id": {"type": "$type", "severity": "$severity"},
                    "count": {"$sum": 1}
                }}
            ]).to_list(None)
            
            # Process vulnerability stats
            vulnerabilities_found = {}
            severity_distribution = {}
            for stat in vuln_stats:
                vuln_type = (stat["_id"]["type"] or "").lower()
                severity = stat["_id"]["severity"]
                count = stat["count"]
                
                vulnerabilities_found[vuln_type] = vulnerabilities_found.get(vuln_type, 0) + count
                severity_distribution[severity] = severity_distribution.get(severity, 0) + count
            
            # Create analytics document
            analytics_data = AnalyticsDocument(
                date=date,
                total_scans=scan_stats[0]["total_scans"] if scan_stats else 0,
                completed_scans=scan_stats[0]["completed_scans"] if scan_stats else 0,
                failed_scans=scan_stats[0]["failed_scans"] if scan_stats else 0,
                vulnerabilities_found=vulnerabilities_found,
                severity_distribution=severity_distribution,
                avg_scan_time=scan_stats[0]["avg_scan_time"] if scan_stats else None
            )
            
            # Upsert analytics
            await analytics_collection.replace_one(
                {"date": date},
                analytics_data.dict(),
                upsert=True
            )
            
            logger.info(f"Updated analytics for {date}")
            
        except Exception as e:
            logger.error(f"Failed to update analytics: {e}")
    
    async def get_analytics(self, days: int = 30) -> Dict[str, Any]:
        """Get analytics for the last N days"""
        try:
            analytics_collection = mongodb.db.analytics
            
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")
            
            # Exclude MongoDB _id to avoid JSON encoding errors
            cursor = analytics_collection.find(
                {"date": {"$gte": start_date_str, "$lte": end_date_str}},
                {"_id": 0}
            ).sort("date", 1)
            
            analytics_data = await cursor.to_list(length=days)
            # Normalize any datetime fields for JSON (e.g., updated_at)
            for item in analytics_data:
                try:
                    if isinstance(item.get("updated_at"), datetime):
                        item["updated_at"] = item["updated_at"].isoformat()
                except Exception:
                    pass
            
            # Process data for trends
            vulnerability_trends = {}
            total_scans = 0
            total_completed = 0
            
            for day_data in analytics_data:
                total_scans += day_data.get("total_scans", 0)
                total_completed += day_data.get("completed_scans", 0)
                
                for vuln_type, count in day_data.get("vulnerabilities_found", {}).items():
                    vuln_type = (vuln_type or "").lower()
                    if vuln_type not in vulnerability_trends:
                        vulnerability_trends[vuln_type] = []
                    vulnerability_trends[vuln_type].append({
                        "date": day_data["date"],
                        "count": count
                    })
            
            # Calculate success rate
            success_rate = (total_completed / total_scans * 100) if total_scans > 0 else 0
            
            return {
                "date_range": f"{start_date_str} to {end_date_str}",
                "total_scans": total_scans,
                "vulnerability_trends": vulnerability_trends,
                "scan_success_rate": round(success_rate, 2),
                "daily_data": analytics_data
            }
            
        except Exception as e:
            logger.error(f"Failed to get analytics: {e}")
            return {}

# Global service instance
mongo_service = MongoService()
