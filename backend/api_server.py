from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import asyncio
import json
import threading
import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel
import os
import sys
import time
from datetime import datetime

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules from the backend directory
from crawler import Crawler
from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.csrf_scanner import CSRFScanner
from vuln_enrichment import groq_ai_enrich, enrich_finding
from vulnerability import Vulnerability

# Import MongoDB components
from database import mongodb
from mongo_service import mongo_service
from models import ScanDocument, VulnerabilityDocument, ScanLogEntry, ScanStatus

app = FastAPI(title="VulnPy GUI API", version="1.0.0")

# MongoDB lifecycle management
@app.on_event("startup")
async def startup_event():
    await mongodb.connect()

@app.on_event("shutdown")
async def shutdown_event():
    await mongodb.close()

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:5173", "http://127.0.0.1:8080"],  # Vite default ports
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state management
class ScanState:
    def __init__(self):
        self.current_scan_id: Optional[str] = None
        self.is_scanning: bool = False
        self.scan_progress: int = 0
        self.current_phase: str = "idle"
        self.vulnerabilities: List[Dict] = []
        self.scan_stats: Dict = {
            "urls_crawled": 0,
            "forms_found": 0,
            "requests_sent": 0,
            "vulnerabilities_found": 0,
            "ai_calls_made": 0
        }
        self.scan_log: List[Dict] = []
        self.scan_config: Dict = {}

scan_state = ScanState()

# Pydantic models for API requests
class ScanRequest(BaseModel):
    target_url: str
    scan_types: List[str] = ["xss", "sqli", "csrf"]
    mode: str = "fast"  # fast or full
    headless: bool = False
    oast: bool = False
    ai_calls: int = 30
    verbose: bool = False
    max_depth: int = 3
    delay: float = 1.0

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class VulnerabilityResponse(BaseModel):
    id: str
    type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    remediation: str
    cvss: float
    epss: float
    severity: str
    ai_summary: Optional[str] = None
    confidence: str
    timestamp: str

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_message(self, message: dict):
        for connection in self.active_connections[:]:  # Copy list to avoid modification during iteration
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                # Remove disconnected clients
                if connection in self.active_connections:
                    self.active_connections.remove(connection)

manager = ConnectionManager()

def add_log_entry(message: str, level: str = "info", scan_id: str = None, phase: str = "general"):
    """Add entry to scan log"""
    timestamp = datetime.now()
    log_entry = {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "level": level
    }
    scan_state.scan_log.append(log_entry)
    
    # Save to MongoDB if scan_id is provided
    if scan_id:
        log_document = ScanLogEntry(
            scan_id=scan_id,
            timestamp=timestamp,
            level=level,
            message=message,
            phase=phase
        )
        asyncio.create_task(mongo_service.add_scan_log(log_document))
    
    # Send log update via WebSocket
    asyncio.create_task(manager.send_message({
        "type": "log_update",
        "entry": log_entry
    }))

def convert_finding_to_dict(finding):
    """Convert finding object to dictionary for JSON serialization"""
    return {
        "id": str(uuid.uuid4()),
        "type": finding.vulnerability_type,
        "url": finding.url,
        "parameter": finding.parameter,
        "payload": finding.payload,
        "evidence": finding.evidence,
        "remediation": getattr(finding, 'remediation', 'No remediation available'),
        "cvss": getattr(finding, 'cvss', 0.0),
        "epss": getattr(finding, 'epss', 0.0),
        "severity": getattr(finding, 'severity', 'Unknown'),
        "ai_summary": getattr(finding, 'ai_summary', None),
        "confidence": finding.confidence,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# API Endpoints
@app.get("/")
async def root():
    return {"message": "VulnPy GUI API Server", "status": "running", "version": "1.0.0"}

@app.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    if scan_state.is_scanning:
        return ScanResponse(
            scan_id="",
            status="error",
            message="A scan is already in progress"
        )
    
    scan_id = str(uuid.uuid4())
    scan_state.current_scan_id = scan_id
    scan_state.is_scanning = True
    scan_state.scan_progress = 0
    scan_state.current_phase = "starting"
    scan_state.vulnerabilities = []
    scan_state.scan_log = []
    scan_state.scan_config = scan_request.dict()
    scan_state.scan_stats = {
        "urls_crawled": 0,
        "forms_found": 0,
        "requests_sent": 0,
        "vulnerabilities_found": 0,
        "ai_calls_made": 0
    }
    
    # Create scan document in MongoDB
    scan_document = ScanDocument(
        scan_id=scan_id,
        target_url=scan_request.target_url,
        scan_types=scan_request.scan_types,
        mode=scan_request.mode,
        status=ScanStatus.SCANNING,
        config={
            "headless": scan_request.headless,
            "oast": scan_request.oast,
            "ai_calls": scan_request.ai_calls,
            "verbose": scan_request.verbose,
            "max_depth": scan_request.max_depth,
            "delay": scan_request.delay
        },
        vulnerabilities_found=0,
        total_time=None
    )
    
    try:
        await mongo_service.create_scan(scan_document)
        add_log_entry(f"Starting scan for {scan_request.target_url}", "info", scan_id)
        
        # Start scan in background
        background_tasks.add_task(run_scan, scan_request, scan_id)
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message="Scan started successfully"
        )
    except Exception as e:
        scan_state.is_scanning = False
        return ScanResponse(
            scan_id="",
            status="error",
            message=f"Failed to create scan: {str(e)}"
        )

@app.get("/api/scan/status")
async def get_scan_status():
    return {
        "scan_id": scan_state.current_scan_id,
        "is_scanning": scan_state.is_scanning,
        "progress": scan_state.scan_progress,
        "phase": scan_state.current_phase,
        "stats": scan_state.scan_stats,
        "config": scan_state.scan_config
    }

# ==================== NEW MONGODB ENDPOINTS ====================

@app.get("/api/scan/history")
async def get_scan_history(
    page: int = 1,
    per_page: int = 20,
    status: Optional[str] = None,
    target_url: Optional[str] = None,
    scan_type: Optional[str] = None
):
    """Get scan history with filtering and pagination"""
    try:
        result = await mongo_service.get_scan_history(
            page=page,
            per_page=per_page,
            status=status,
            target_url=target_url,
            scan_type=scan_type
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan history: {str(e)}")

@app.get("/api/scan/logs")
async def get_scan_logs(scan_id: str = Query(None)):
    """Get scan logs, optionally filtered by scan_id"""
    try:
        if scan_id:
            # Get logs for specific scan from MongoDB
            logs = await mongo_service.get_scan_logs(scan_id)
            return {
                "logs": logs,
                "total": len(logs),
                "scan_id": scan_id
            }
        else:
            # Get current scan logs from memory
            return {
                "logs": scan_state.scan_log,
                "total": len(scan_state.scan_log)
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan logs: {str(e)}")

@app.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get detailed information about a specific scan"""
    try:
        scan = await mongo_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities for this scan
        vulnerabilities = await mongo_service.get_vulnerabilities(scan_id=scan_id)
        
        # Get logs for this scan
        logs = await mongo_service.get_scan_logs(scan_id)
        
        return {
            "scan": scan,
            "vulnerabilities": vulnerabilities,
            "logs": logs
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan details: {str(e)}")

@app.get("/api/vulnerabilities/search")
async def search_vulnerabilities(
    scan_id: Optional[str] = None,
    vuln_type: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
):
    """Search and filter vulnerabilities"""
    try:
        result = await mongo_service.get_vulnerabilities(
            scan_id=scan_id,
            vuln_type=vuln_type,
            severity=severity,
            page=page,
            per_page=per_page
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search vulnerabilities: {str(e)}")

@app.get("/api/analytics")
async def get_analytics(days: int = 30):
    """Get analytics data for the last N days"""
    try:
        # Update analytics for today before returning
        await mongo_service.update_analytics()
        
        result = await mongo_service.get_analytics(days=days)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analytics: {str(e)}")

@app.post("/api/analytics/update")
async def update_analytics(date: Optional[str] = None):
    """Manually update analytics for a specific date"""
    try:
        await mongo_service.update_analytics(date)
        return {"status": "success", "message": f"Analytics updated for {date or 'today'}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update analytics: {str(e)}")

@app.post("/api/scan/stop")
async def stop_scan():
    if not scan_state.is_scanning:
        return {"status": "error", "message": "No scan is currently running"}
    
    scan_state.is_scanning = False
    scan_state.current_phase = "stopped"
    add_log_entry("Scan stopped by user", "warning")
    
    await manager.send_message({
        "type": "scan_stopped",
        "message": "Scan stopped by user"
    })
    
    return {"status": "stopped", "message": "Scan stopped successfully"}

@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    return {
        "vulnerabilities": scan_state.vulnerabilities,
        "total": len(scan_state.vulnerabilities),
        "by_type": {
            "xss": len([v for v in scan_state.vulnerabilities if v["type"].lower() == "xss"]),
            "sqli": len([v for v in scan_state.vulnerabilities if v["type"].lower() == "sqli"]),
            "csrf": len([v for v in scan_state.vulnerabilities if v["type"].lower() == "csrf"])
        }
    }

@app.post("/api/ai/enrich")
async def enrich_vulnerabilities():
    if not scan_state.vulnerabilities:
        return {"status": "error", "message": "No vulnerabilities to enrich"}
    
    try:
        add_log_entry("Starting AI enrichment...", "info", None, "enriching")
        
        # Convert dict back to finding objects for AI enrichment
        class MockFinding:
            def __init__(self, vuln_dict):
                self.vulnerability_type = vuln_dict["type"]
                self.url = vuln_dict["url"]
                self.parameter = vuln_dict["parameter"]
                self.payload = vuln_dict["payload"]
                self.evidence = vuln_dict["evidence"]
                self.confidence = vuln_dict["confidence"]
        
        mock_findings = [MockFinding(v) for v in scan_state.vulnerabilities]
        enriched_findings = groq_ai_enrich(mock_findings)
        
        # Update the stored vulnerabilities with AI summaries
        for i, finding in enumerate(enriched_findings):
            if hasattr(finding, 'ai_summary'):
                scan_state.vulnerabilities[i]["ai_summary"] = finding.ai_summary
        
        add_log_entry("AI enrichment completed", "info", None, "enriching")
        
        await manager.send_message({
            "type": "ai_enrichment_complete",
            "message": "AI enrichment completed",
            "enriched_count": len(enriched_findings)
        })
        
        return {"status": "success", "message": "AI enrichment completed"}
    except Exception as e:
        add_log_entry(f"AI enrichment failed: {str(e)}", "error")
        return {"status": "error", "message": f"AI enrichment failed: {str(e)}"}

@app.websocket("/ws/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception as e:
        manager.disconnect(websocket)

# Background scan function
async def run_scan(scan_request: ScanRequest, scan_id: str):
    try:
        await manager.send_message({
            "type": "scan_started",
            "scan_id": scan_id,
            "target": scan_request.target_url
        })
        
        # Phase 1: Crawling
        scan_state.current_phase = "crawling"
        scan_state.scan_progress = 10
        add_log_entry("Starting website crawling...", "info", scan_id, "crawling")
        
        await manager.send_message({
            "type": "phase_update",
            "phase": "crawling",
            "progress": 10
        })
        
        # Initialize crawler
        crawler = Crawler(scan_request.target_url, max_depth=scan_request.max_depth, verbose=scan_request.verbose)
        attack_surface = crawler.crawl()
        
        scan_state.scan_stats["urls_crawled"] = len(attack_surface['urls'])
        scan_state.scan_stats["forms_found"] = len(attack_surface['forms'])
        
        scan_state.scan_progress = 30
        add_log_entry(f"Crawling complete: {len(attack_surface['urls'])} URLs, {len(attack_surface['forms'])} forms found")
        
        await manager.send_message({
            "type": "crawling_complete",
            "urls_found": len(attack_surface['urls']),
            "forms_found": len(attack_surface['forms']),
            "progress": 30
        })
        
        # Phase 2: Vulnerability Scanning
        scan_state.current_phase = "scanning"
        scan_state.scan_progress = 40
        add_log_entry("Starting vulnerability scanning...", "info", scan_id, "scanning")
        
        all_findings = []
        
        # Load payloads based on mode
        payload_limit = 10 if scan_request.mode == "fast" else None
        
        # XSS Scanning
        if "xss" in scan_request.scan_types and scan_state.is_scanning:
            add_log_entry("Scanning for XSS vulnerabilities...", "info", scan_id, "scanning")
            try:
                with open('payloads/xss_payloads.txt', 'r') as f:
                    xss_payloads = [line.strip() for line in f if line.strip()]
                    if payload_limit:
                        xss_payloads = xss_payloads[:payload_limit]
                
                # Create session for XSSScanner
                import requests
                session = requests.Session()
                session.headers.update({'User-Agent': 'VulnPy GUI/1.0'})
                
                xss_scanner = XSSScanner(session, xss_payloads, verbose=scan_request.verbose)
                xss_findings = xss_scanner.scan(attack_surface)
                
                for finding in xss_findings:
                    enrich_finding(finding)
                
                xss_dicts = [convert_finding_to_dict(f) for f in xss_findings]
                all_findings.extend(xss_dicts)
                scan_state.vulnerabilities.extend(xss_dicts)
                
                # Save vulnerabilities to MongoDB
                for vuln_dict in xss_dicts:
                    vuln_document = VulnerabilityDocument(
                        scan_id=scan_id,
                        url=vuln_dict["url"],
                        parameter=vuln_dict["parameter"],
                        payload=vuln_dict["payload"],
                        evidence=vuln_dict["evidence"],
                        type=vuln_dict["type"],
                        severity=vuln_dict["severity"],
                        confidence=vuln_dict["confidence"],
                        remediation=vuln_dict.get("remediation"),
                        cvss_score=vuln_dict.get("cvss", 0.0),
                        epss_score=vuln_dict.get("epss", 0.0),
                        ai_summary=vuln_dict.get("ai_summary")
                    )
                    await mongo_service.create_vulnerability(vuln_document)
                
                add_log_entry(f"XSS scan complete: {len(xss_findings)} vulnerabilities found", "info", scan_id)
                
                await manager.send_message({
                    "type": "vulnerabilities_found",
                    "scanner": "XSS",
                    "count": len(xss_findings),
                    "vulnerabilities": xss_dicts
                })
            except Exception as e:
                add_log_entry(f"XSS scanning error: {str(e)}", "error")
        
        scan_state.scan_progress = 60
        
        # SQLi Scanning
        if "sqli" in scan_request.scan_types and scan_state.is_scanning:
            add_log_entry("Scanning for SQL injection vulnerabilities...", "info", scan_id, "scanning")
            try:
                # Load SQLi payloads
                import json
                sqli_payloads = []
                try:
                    with open('payloads/sqli_payloads.json', 'r') as f:
                        sqli_payloads = json.load(f)
                        if payload_limit:
                            sqli_payloads = sqli_payloads[:payload_limit]
                except FileNotFoundError:
                    add_log_entry("SQLi payloads file not found, using default payloads", "warning")
                    sqli_payloads = ["' OR '1'='1' -- ", "\" OR \"1\"=\"1\" -- ", "' OR 1=1#"]
                
                # Create session for SQLiScanner
                import requests
                session = requests.Session()
                session.headers.update({'User-Agent': 'VulnPy GUI/1.0'})
                
                sqli_scanner = SQLiScanner(session, sqli_payloads, verbose=scan_request.verbose)
                sqli_findings = sqli_scanner.scan(attack_surface)
                
                for finding in sqli_findings:
                    enrich_finding(finding)
                
                sqli_dicts = [convert_finding_to_dict(f) for f in sqli_findings]
                all_findings.extend(sqli_dicts)
                scan_state.vulnerabilities.extend(sqli_dicts)
                
                # Save vulnerabilities to MongoDB
                for vuln_dict in sqli_dicts:
                    vuln_document = VulnerabilityDocument(
                        scan_id=scan_id,
                        url=vuln_dict["url"],
                        parameter=vuln_dict["parameter"],
                        payload=vuln_dict["payload"],
                        evidence=vuln_dict["evidence"],
                        type=vuln_dict["type"],
                        severity=vuln_dict["severity"],
                        confidence=vuln_dict["confidence"],
                        remediation=vuln_dict.get("remediation"),
                        cvss_score=vuln_dict.get("cvss", 0.0),
                        epss_score=vuln_dict.get("epss", 0.0),
                        ai_summary=vuln_dict.get("ai_summary")
                    )
                    await mongo_service.create_vulnerability(vuln_document)
                
                add_log_entry(f"SQLi scan complete: {len(sqli_findings)} vulnerabilities found", "info", scan_id)
                
                await manager.send_message({
                    "type": "vulnerabilities_found",
                    "scanner": "SQLi",
                    "count": len(sqli_findings),
                    "vulnerabilities": sqli_dicts
                })
            except Exception as e:
                add_log_entry(f"SQLi scanning error: {str(e)}", "error")
        
        scan_state.scan_progress = 80
        
        # CSRF Scanning
        if "csrf" in scan_request.scan_types and scan_state.is_scanning:
            add_log_entry("Scanning for CSRF vulnerabilities...", "info", scan_id, "scanning")
            try:
                # Create session for CSRFScanner
                import requests
                session = requests.Session()
                session.headers.update({'User-Agent': 'VulnPy GUI/1.0'})
                
                csrf_scanner = CSRFScanner(session, verbose=scan_request.verbose)
                csrf_findings = csrf_scanner.scan(attack_surface)
                
                for finding in csrf_findings:
                    enrich_finding(finding)
                
                csrf_dicts = [convert_finding_to_dict(f) for f in csrf_findings]
                all_findings.extend(csrf_dicts)
                scan_state.vulnerabilities.extend(csrf_dicts)
                
                # Save vulnerabilities to MongoDB
                for vuln_dict in csrf_dicts:
                    vuln_document = VulnerabilityDocument(
                        scan_id=scan_id,
                        url=vuln_dict["url"],
                        parameter=vuln_dict["parameter"],
                        payload=vuln_dict["payload"],
                        evidence=vuln_dict["evidence"],
                        type=vuln_dict["type"],
                        severity=vuln_dict["severity"],
                        confidence=vuln_dict["confidence"],
                        remediation=vuln_dict.get("remediation"),
                        cvss_score=vuln_dict.get("cvss", 0.0),
                        epss_score=vuln_dict.get("epss", 0.0),
                        ai_summary=vuln_dict.get("ai_summary")
                    )
                    await mongo_service.create_vulnerability(vuln_document)
                
                add_log_entry(f"CSRF scan complete: {len(csrf_findings)} vulnerabilities found", "info", scan_id)
                
                await manager.send_message({
                    "type": "vulnerabilities_found",
                    "scanner": "CSRF",
                    "count": len(csrf_findings),
                    "vulnerabilities": csrf_dicts
                })
            except Exception as e:
                add_log_entry(f"CSRF scanning error: {str(e)}", "error")
        
        scan_state.scan_stats["vulnerabilities_found"] = len(all_findings)
        scan_state.scan_progress = 90
        
        # Phase 3: AI Enrichment (if requested)
        if scan_request.ai_calls > 0 and all_findings and scan_state.is_scanning:
            scan_state.current_phase = "ai_analysis"
            add_log_entry(f"Starting AI enrichment for top {min(scan_request.ai_calls, len(all_findings))} vulnerabilities...")
            
            await manager.send_message({
                "type": "phase_update",
                "phase": "ai_analysis",
                "progress": 90
            })
            
            try:
                # Convert dict findings back to Vulnerability objects for AI enrichment
                vuln_objects = []
                for finding_dict in all_findings:
                    vuln = Vulnerability(
                        vulnerability_type=finding_dict["type"],
                        url=finding_dict["url"],
                        parameter=finding_dict["parameter"],
                        payload=finding_dict["payload"],
                        evidence=finding_dict["evidence"],
                        confidence=finding_dict.get("confidence", "Medium"),
                        remediation=finding_dict.get("remediation", None),
                        cvss=finding_dict.get("cvss", 0.0),
                        epss=finding_dict.get("epss", 0.0),
                        severity=finding_dict.get("severity", "Unknown"),
                        ai_summary=finding_dict.get("ai_summary", None)
                    )
                    vuln_objects.append(vuln)
                
                # Perform AI enrichment
                enriched_vulns = groq_ai_enrich(vuln_objects, scan_request.ai_calls)
                
                # Update the stored vulnerabilities with AI summaries
                for i, vuln in enumerate(enriched_vulns):
                    if i < len(scan_state.vulnerabilities):
                        scan_state.vulnerabilities[i]["ai_summary"] = getattr(vuln, 'ai_summary', None)
                        scan_state.vulnerabilities[i]["remediation"] = getattr(vuln, 'remediation', scan_state.vulnerabilities[i].get("remediation"))
                        scan_state.vulnerabilities[i]["cvss"] = getattr(vuln, 'cvss', scan_state.vulnerabilities[i].get("cvss", 0.0))
                        scan_state.vulnerabilities[i]["epss"] = getattr(vuln, 'epss', scan_state.vulnerabilities[i].get("epss", 0.0))
                        scan_state.vulnerabilities[i]["severity"] = getattr(vuln, 'severity', scan_state.vulnerabilities[i].get("severity", "Unknown"))
                
                scan_state.scan_stats["ai_calls_made"] = min(scan_request.ai_calls, len(all_findings))
                add_log_entry("AI enrichment completed")
                
                await manager.send_message({
                    "type": "ai_enrichment_complete",
                    "enriched_count": len([v for v in scan_state.vulnerabilities if v.get("ai_summary")])
                })
                
            except Exception as e:
                add_log_entry(f"AI enrichment error: {str(e)}", "error")
        
        # Scan complete
        if scan_state.is_scanning:  # Only mark complete if not stopped
            scan_state.current_phase = "complete"
            scan_state.scan_progress = 100
            add_log_entry(f"Scan completed: {len(all_findings)} total vulnerabilities found", "info", scan_id)
            
            # Update scan document in MongoDB
            scan_update = {
                "status": ScanStatus.COMPLETED,
                "vulnerabilities_found": len(all_findings),
                "stats": scan_state.scan_stats,
                "total_time": None  # You might want to calculate this
            }
            await mongo_service.update_scan(scan_id, scan_update)
            
            # Update analytics
            await mongo_service.update_analytics()
            
            await manager.send_message({
                "type": "scan_complete",
                "total_vulnerabilities": len(all_findings),
                "by_type": {
                    "xss": len([v for v in all_findings if v["type"].lower() == "xss"]),
                    "sqli": len([v for v in all_findings if v["type"].lower() == "sqli"]),
                    "csrf": len([v for v in all_findings if v["type"].lower() == "csrf"])
                },
                "progress": 100
            })
        
        scan_state.is_scanning = False
        
    except Exception as e:
        scan_state.is_scanning = False
        scan_state.current_phase = "error"
        add_log_entry(f"Scan error: {str(e)}", "error", scan_id)
        
        # Update scan status as failed in MongoDB
        scan_update = {
            "status": ScanStatus.FAILED,
            "error_message": str(e)
        }
        await mongo_service.update_scan(scan_id, scan_update)
        
        await manager.send_message({
            "type": "scan_error",
            "error": str(e)
        })

if __name__ == "__main__":
    import uvicorn
    print("Starting VulnPy GUI API Server...")
    print("Backend will be available at: http://localhost:8000")
    print("API docs available at: http://localhost:8000/docs")
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=False)
