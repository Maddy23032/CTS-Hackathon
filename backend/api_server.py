from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import asyncio
import json
import threading
import uuid
from typing import Dict, List, Optional, Any
from pydantic import BaseModel
import os
import sys
from datetime import datetime
from scanner import VulnerabilityScanner
from real_time_scanner import RealTimeScanner

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules from the backend directory
from crawler import Crawler
from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.csrf_scanner import CSRFScanner
from vuln_enrichment import groq_ai_enrich, enrich_finding
from vulnerability import Vulnerability
from oast_collaborator import oast_collaborator

# Import MongoDB components
from database import mongodb
from mongo_service import mongo_service
from models import ScanDocument, VulnerabilityDocument, ScanLogEntry, ScanStatus

app = FastAPI(title="VulnPy GUI API", version="1.0.0")

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# MongoDB lifecycle management
@app.on_event("startup")
async def startup_event():
    try:
        await mongodb.connect()
        print("✅ MongoDB connected successfully")
    except Exception as e:
        print(f"⚠️  MongoDB connection failed: {e}")
        print("📝 Running in MongoDB-optional mode. Some features may be limited.")
        
    try:
        await oast_collaborator.initialize()
        print("✅ OAST collaborator initialized")
    except Exception as e:
        print(f"⚠️  OAST initialization failed: {e}")
        
    print("🚀 Server startup completed!")

@app.on_event("shutdown")
async def shutdown_event():
    try:
        await mongodb.close()
    except:
        pass
    try:
        await oast_collaborator.cleanup()
    except:
        pass

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
        self.current_url: Optional[str] = None
        self.current_payload: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.vulnerabilities: List[Dict] = []
        self.cancel_requested: bool = False
        self.current_scanner: Optional[Any] = None
        self.scan_stats: Dict = {
            "urls_crawled": 0,
            "forms_found": 0,
            "requests_sent": 0,
            "vulnerabilities_found": 0,
            "ai_calls_made": 0,
        }
        self.phase_details: Dict = {
            "crawl_queue_size": 0,
            "scan_queue_size": 0,
            "current_depth": 0,
            "max_depth": 3,
        }
        self.scan_log: List[Dict] = []
        self.scan_config: Dict = {}
        
    def get_elapsed_time(self) -> int:
        """Get elapsed time in seconds since scan started"""
        if self.start_time:
            return int((datetime.now() - self.start_time).total_seconds())
        return 0

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

class OASTConfig(BaseModel):
    collaborator_url: str
    auth_token: Optional[str] = None
    enabled: bool = True

class OASTCallbackData(BaseModel):
    payload_id: str
    source_ip: str
    method: str
    headers: Dict[str, str]
    body: str
    url: str
    vulnerability_type: str
    scan_id: Optional[str] = None

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
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        await self.send_message(message)

manager = ConnectionManager()

def add_log_entry(message: str, level: str = "info", scan_id: str = None, phase: str = "general"):
    """Add entry to scan log and broadcast it."""
    timestamp = datetime.now()
    log_entry = {
        "timestamp": timestamp.isoformat(),
        "message": message,
        "level": level,
        "phase": phase,
        "scan_id": scan_id or scan_state.current_scan_id
    }
    scan_state.scan_log.append(log_entry)

    # Broadcast the log entry via WebSocket
    # This needs to run in the event loop.
    async def broadcast_log():
        try:
            await manager.broadcast({
                "type": "scan_log",
                "data": log_entry
            })
        except Exception as e:
            print(f"Error broadcasting log: {e}")

    # Schedule the broadcast on the main event loop
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcast_log())
    except RuntimeError:  # No running loop
        # This can happen if called from a non-async context.
        # For simplicity, we'll just print. A more robust solution
        # might involve a queue.
        print(f"Log (no loop): {message}")


    # Save to MongoDB if scan_id is provided and connection is available
    if scan_id and mongodb.is_connected():
        async def save_log_to_db():
            try:
                mongo_log_entry = ScanLogEntry(**log_entry)
                await mongo_service.add_scan_log(mongo_log_entry)
            except Exception as e:
                print(f"MongoDB log saving error: {e}")
        
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(save_log_to_db())
        except RuntimeError:
            pass # Cannot save to DB without a loop

async def run_real_time_scan(scan_request: ScanRequest, scan_id: str):
    """Run scan using the integrated RealTimeScanner and handle real-time updates."""
    add_log_entry(
        f"Initializing scan for {scan_request.target_url}",
        "info",
        scan_id,
        "starting",
    )

    try:
        # Callback for centralized logging
        def log_handler(message, level="INFO", **kwargs):
            current_scan_id = kwargs.get("scan_id", scan_id)
            add_log_entry(message, level, current_scan_id)

        # Initialize the real-time scanner with the log_callback
        scanner = RealTimeScanner(
            target_url=scan_request.target_url,
            scan_types=scan_request.scan_types,
            verbose=scan_request.verbose,
            delay=scan_request.delay / 1000,  # Convert ms to seconds
            websocket_manager=manager,
            log_callback=log_handler,
        )
        scanner.set_scan_id(scan_id)
        scan_state.current_scanner = scanner

        # Run the scan
        vulnerabilities = await scanner.run_scan()

        scan_state.is_scanning = False
        scan_state.current_phase = "completed"
        scan_state.scan_progress = 100

        # Persist discovered vulnerabilities in memory for REST fallback
        try:
            scan_state.vulnerabilities = [
                convert_finding_to_dict(v) if not isinstance(v, dict) else v
                for v in vulnerabilities
            ]
        except Exception:
            pass

        # Update scan status in MongoDB
        if mongodb.is_connected():
            try:
                await mongo_service.update_scan(
                    scan_id,
                    {
                        "status": ScanStatus.COMPLETED,
                        "vulnerabilities_found": len(vulnerabilities),
                        "total_time": scan_state.get_elapsed_time(),
                    },
                )
            except Exception as e:
                print(f"MongoDB update scan error (continuing): {e}")

        add_log_entry(
            f"Scan completed. Found {len(vulnerabilities)} vulnerabilities.",
            "info",
            scan_id,
            "completed",
        )

    except Exception as e:
        scan_state.is_scanning = False
        scan_state.current_phase = "error"
        error_msg = f"Scan failed: {e}"
        import traceback

        traceback.print_exc()
        add_log_entry(error_msg, "error", scan_id, "error")

        # Update scan status in MongoDB
        if mongodb.is_connected():
            try:
                await mongo_service.update_scan(
                    scan_id,
                    {"status": ScanStatus.FAILED, "error_message": error_msg},
                )
            except Exception as e:
                print(f"MongoDB update scan (failed) error (continuing): {e}")

        # Send error message via WebSocket
        await manager.send_message(
            {"type": "error", "message": error_msg, "scan_id": scan_id}
        )
    finally:
        scan_state.current_scanner = None


async def parse_scan_output(line: str):
    """Parse CLI output and update scan state accordingly"""
    try:
        line_lower = line.lower()
        
        # Update current URL being processed
        if "crawling:" in line_lower or "testing:" in line_lower:
            # Extract URL from the line
            if "http" in line:
                import re
                url_match = re.search(r'https?://[^\s]+', line)
                if url_match:
                    scan_state.current_url = url_match.group()
        
        # Update current payload being tested
        if "payload:" in line_lower or "injecting:" in line_lower:
            # Extract payload (usually after the URL or "payload:" keyword)
            payload_start = line.find("payload:")
            if payload_start > -1:
                scan_state.current_payload = line[payload_start + 8:].strip()
            elif "'" in line or "<" in line or "SELECT" in line.upper():
                # Try to extract common payload patterns
                scan_state.current_payload = line.split()[-1] if line.split() else None
        
        # Update statistics based on output
        if "found form" in line_lower:
            scan_state.scan_stats["forms_found"] += 1
        elif "discovered" in line_lower and "url" in line_lower:
            scan_state.scan_stats["urls_crawled"] += 1
        elif "request sent" in line_lower or "testing parameter" in line_lower:
            scan_state.scan_stats["requests_sent"] += 1
        elif "vulnerability found" in line_lower or "xss detected" in line_lower or "sqli detected" in line_lower:
            scan_state.scan_stats["vulnerabilities_found"] += 1
        elif "ai analysis" in line_lower:
            scan_state.scan_stats["ai_calls_made"] += 1
        
        # Update phase based on output
        if "crawling" in line_lower:
            scan_state.current_phase = "crawling"
            scan_state.scan_progress = min(30, scan_state.scan_progress + 1)
        elif "scanning" in line_lower or "testing" in line_lower:
            scan_state.current_phase = "scanning"
            scan_state.scan_progress = min(80, max(30, scan_state.scan_progress + 1))
        elif "ai" in line_lower and "analysis" in line_lower:
            scan_state.current_phase = "ai_analysis"
            scan_state.scan_progress = min(95, max(80, scan_state.scan_progress + 1))
        elif "completed" in line_lower or "finished" in line_lower:
            scan_state.current_phase = "completed"
            scan_state.scan_progress = 100
            
    except Exception as e:
        print(f"[DEBUG] Error parsing output: {e}")
        # Continue anyway, don't break the scan

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
    scan_state.current_url = None
    scan_state.current_payload = None
    scan_state.start_time = datetime.now()
    scan_state.vulnerabilities = []
    scan_state.scan_log = []
    scan_state.scan_config = scan_request.dict()
    scan_state.cancel_requested = False
    scan_state.current_scanner = None
    scan_state.scan_stats = {
        "urls_crawled": 0,
        "forms_found": 0,
        "requests_sent": 0,
        "vulnerabilities_found": 0,
        "ai_calls_made": 0
    }
    scan_state.phase_details = {
        "crawl_queue_size": 0,
        "scan_queue_size": 0,
        "current_depth": 0,
        "max_depth": scan_request.max_depth
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
        # Try to create scan document in MongoDB, but don't fail if it doesn't work
        try:
            await mongo_service.create_scan(scan_document)
        except Exception as mongo_error:
            print(f"MongoDB error (continuing anyway): {mongo_error}")
            
        # Simple log entry without MongoDB dependency  
        print(f"[DEBUG] Starting scan for {scan_request.target_url}")
        
        # Start scan in background
        background_tasks.add_task(run_real_time_scan, scan_request, scan_id)
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message="Scan started successfully"
        )
    except Exception as e:
        print(f"Scan start error: {e}")
        scan_state.is_scanning = False
        return ScanResponse(
            scan_id="",
            status="error",
            message=f"Failed to start scan: {str(e)}"
        )

@app.get("/api/scan/status")
async def get_scan_status():
    return {
        "scan_id": scan_state.current_scan_id,
        "is_scanning": scan_state.is_scanning,
        "progress": scan_state.scan_progress,
        "phase": scan_state.current_phase,
        "current_url": scan_state.current_url,
        "current_payload": scan_state.current_payload,
        "start_time": scan_state.start_time.isoformat() if scan_state.start_time else None,
        "elapsed_time": scan_state.get_elapsed_time(),
        "stats": scan_state.scan_stats,
        "phase_details": scan_state.phase_details,
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
    
    # Request cooperative cancellation
    scan_state.cancel_requested = True
    try:
        scanner = scan_state.current_scanner
        if scanner is not None and hasattr(scanner, 'cancel'):
            scanner.cancel()
    except Exception:
        pass

    scan_state.is_scanning = False
    scan_state.current_phase = "stopped"
    add_log_entry("Scan stopped by user", "warning")

    # Update MongoDB status if connected
    if mongodb.is_connected() and scan_state.current_scan_id:
        try:
            await mongo_service.update_scan(
                scan_state.current_scan_id,
                {
                    "status": ScanStatus.CANCELLED,
                    "total_time": scan_state.get_elapsed_time(),
                },
            )
        except Exception as e:
            print(f"MongoDB update scan (cancelled) error (continuing): {e}")
    
    await manager.send_message({
        "type": "scan_stopped",
        "message": "Scan stopped by user"
    })
    
    return {"status": "stopped", "message": "Scan stopped successfully"}

@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    # Build dynamic counts by vulnerability type to include all scanners
    by_type: Dict[str, int] = {}
    for v in scan_state.vulnerabilities:
        try:
            t = str(v.get("type", "unknown")).lower()
        except Exception:
            t = "unknown"
        by_type[t] = by_type.get(t, 0) + 1

    return {
        "vulnerabilities": scan_state.vulnerabilities,
        "total": len(scan_state.vulnerabilities),
        "by_type": by_type,
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

# Add a simple WebSocket endpoint for real-time monitoring
@app.websocket("/ws")
async def websocket_scan_monitor(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send heartbeat
            await asyncio.sleep(10)
            await websocket.send_text(json.dumps({"type": "heartbeat", "timestamp": datetime.now().isoformat()}))
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)

@app.websocket("/ws/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception as e:
        manager.disconnect(websocket)

# ==================== OAST ENDPOINTS ====================

@app.post("/api/oast/configure")
async def configure_oast(config: OASTConfig):
    """Configure OAST collaborator settings"""
    try:
        oast_collaborator.collaborator_url = config.collaborator_url
        oast_collaborator.auth_token = config.auth_token
        
        return {
            "status": "success",
            "message": "OAST collaborator configured successfully",
            "config": {
                "collaborator_url": config.collaborator_url,
                "enabled": config.enabled
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to configure OAST: {str(e)}")

@app.get("/api/oast/status")
async def get_oast_status():
    """Get OAST collaborator status and statistics"""
    try:
        stats = oast_collaborator.get_statistics()
        return {
            "status": "active",
            "collaborator_url": oast_collaborator.collaborator_url,
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get OAST status: {str(e)}")

@app.get("/api/oast/payloads")
async def get_oast_payloads(
    scan_id: Optional[str] = None,
    vulnerability_type: Optional[str] = None
):
    """Get OAST payloads"""
    try:
        payloads = oast_collaborator.get_payloads(scan_id=scan_id, vulnerability_type=vulnerability_type)
        return {
            "status": "success",
            "payloads": payloads,
            "total": len(payloads)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get OAST payloads: {str(e)}")

@app.get("/api/oast/callbacks")
async def get_oast_callbacks(
    payload_id: Optional[str] = None,
    scan_id: Optional[str] = None
):
    """Get OAST callbacks"""
    try:
        callbacks = oast_collaborator.get_callbacks(payload_id=payload_id, scan_id=scan_id)
        return {
            "status": "success",
            "callbacks": callbacks,
            "total": len(callbacks)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get OAST callbacks: {str(e)}")

@app.post("/api/oast/callback")
async def register_oast_callback(request: Request):
    """Register an OAST callback (webhook endpoint)"""
    try:
        # Get client IP
        client_ip = request.client.host
        
        # Get request data
        headers = dict(request.headers)
        body = await request.body()
        url = str(request.url)
        method = request.method
        
        # Extract payload ID from URL or headers
        payload_id = request.query_params.get("payload_id", "")
        if not payload_id:
            # Try to extract from URL path
            url_parts = url.split("/")
            if len(url_parts) > 5:
                payload_id = url_parts[-1]
        
        callback_data = {
            "payload_id": payload_id,
            "source_ip": client_ip,
            "method": method,
            "headers": headers,
            "body": body.decode("utf-8", errors="ignore"),
            "url": url,
            "vulnerability_type": "unknown"
        }
        
        success = await oast_collaborator.register_callback(callback_data)
        
        if success:
            # Send WebSocket notification for real-time updates
            await manager.send_message({
                "type": "oast_callback",
                "payload_id": payload_id,
                "source_ip": client_ip,
                "timestamp": datetime.now().isoformat()
            })
            
            return {"status": "success", "message": "Callback registered"}
        else:
            raise HTTPException(status_code=400, detail="Failed to register callback")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register callback: {str(e)}")

@app.post("/api/oast/generate")
async def generate_oast_payloads(
    vulnerability_type: str,
    scan_id: Optional[str] = None
):
    """Generate OAST payloads for a specific vulnerability type"""
    try:
        if vulnerability_type == "xss":
            payloads = oast_collaborator.generate_xss_payloads(scan_id=scan_id)
        elif vulnerability_type == "sqli":
            payloads = oast_collaborator.generate_sqli_payloads(scan_id=scan_id)
        elif vulnerability_type == "command_injection":
            payloads = oast_collaborator.generate_command_injection_payloads(scan_id=scan_id)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported vulnerability type: {vulnerability_type}")
        
        return {
            "status": "success",
            "vulnerability_type": vulnerability_type,
            "payloads": payloads,
            "count": len(payloads)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate payloads: {str(e)}")

@app.delete("/api/oast/cleanup")
async def cleanup_oast_data():
    """Cleanup expired OAST payloads and callbacks"""
    try:
        cleaned_count = oast_collaborator.cleanup_expired_payloads()
        return {
            "status": "success",
            "message": f"Cleaned up {cleaned_count} expired payloads",
            "cleaned_count": cleaned_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup OAST data: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print("Starting VulnPy GUI API Server...")
    print("Backend will be available at: http://localhost:8000")
    print("API docs available at: http://localhost:8000/docs")
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=False)
