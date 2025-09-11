from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
import asyncio
import json
import threading
import uuid
from typing import Dict, List, Optional, Any
from pydantic import BaseModel
import os
import sys
from datetime import datetime, timedelta
from scanner import VulnerabilityScanner
from real_time_scanner import RealTimeScanner

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules from the backend directory
from crawler import Crawler
from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.csrf_scanner import CSRFScanner
from scanners.broken_access_control_scanner import BrokenAccessControlScanner
from scanners.cryptographic_failures_scanner import CryptographicFailuresScanner
from scanners.auth_failures_scanner import AuthenticationFailuresScanner
from scanners.integrity_failures_scanner import IntegrityFailuresScanner
from scanners.logging_monitoring_failures_scanner import LoggingMonitoringFailuresScanner
from vuln_enrichment import groq_ai_enrich, enrich_finding
from vulnerability import Vulnerability
from oast_collaborator import oast_collaborator

# Import MongoDB components
from database import mongodb
from mongo_service import mongo_service
from models import ScanDocument, VulnerabilityDocument, ScanLogEntry, ScanStatus

app = FastAPI(title="VulnScan GUI API", version="1.0.0")

# Get the frontend URL from environment variable
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://vulnscan-nine.vercel.app")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL, 
        "https://vulnscan-nine.vercel.app",
        "https://cts-hackathon-production.up.railway.app",
        "http://localhost:5173", 
        "http://localhost:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add health check endpoint
@app.get("/api/health")
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "message": "VulnScan API is running",
        "version": "1.0.0",
        "environment": "production" if os.getenv("MONGODB_URI") else "development"
    }

# Endpoint to fetch last scan details for persistence
@app.get("/api/scan/last")
async def get_last_scan_details():
    try:
        last_scan = await mongo_service.get_last_scan()
        if not last_scan:
            return {"scan": None, "vulnerabilities": [], "logs": []}
        vulns_response = await mongo_service.get_vulnerabilities(scan_id=last_scan.scan_id)
        vulnerabilities = [v.dict() for v in vulns_response.get("vulnerabilities", [])]
        logs = [l.dict() for l in await mongo_service.get_scan_logs(last_scan.scan_id)]
        return {
            "scan": last_scan.dict(),
            "vulnerabilities": vulnerabilities,
            "logs": logs
        }
    except Exception as e:
        return {"error": str(e)}

# Endpoint to fetch last vulnerabilities only
@app.get("/api/vulnerabilities/last")
async def get_last_vulnerabilities():
    try:
        last_scan = await mongo_service.get_last_scan()
        if not last_scan:
            return {"vulnerabilities": [], "total": 0}
        vulns_response = await mongo_service.get_vulnerabilities(scan_id=last_scan.scan_id)
        vulnerabilities = [v.dict() for v in vulns_response.get("vulnerabilities", [])]
        return {"vulnerabilities": vulnerabilities, "total": len(vulnerabilities)}
    except Exception as e:
        return {"error": str(e)}

# Endpoint to fetch last scan logs only
@app.get("/api/scan/last/logs")
async def get_last_scan_logs():
    try:
        last_scan = await mongo_service.get_last_scan()
        if not last_scan:
            return {"logs": []}
        logs = [l.dict() for l in await mongo_service.get_scan_logs(last_scan.scan_id)]
        return {"logs": logs}
    except Exception as e:
        return {"error": str(e)}
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

    # Restore last scan state from MongoDB if available
    try:
        if mongodb.is_connected():
            last_scan = await mongo_service.get_last_scan()
            if last_scan:
                scan_state.current_scan_id = last_scan.scan_id
                scan_state.is_scanning = False
                scan_state.scan_progress = 100
                scan_state.current_phase = "completed"
                scan_state.current_url = last_scan.target_url
                scan_state.start_time = last_scan.created_at
                scan_state.scan_config = last_scan.dict()
                vulns_response = await mongo_service.get_vulnerabilities(scan_id=last_scan.scan_id)
                scan_state.vulnerabilities = [v.dict() for v in vulns_response.get("vulnerabilities", [])]
                scan_state.scan_log = [l.dict() for l in await mongo_service.get_scan_logs(last_scan.scan_id)]
                print(f"✅ Restored last scan state: {last_scan.scan_id}")
    except Exception as e:
        print(f"⚠️  Failed to restore last scan state: {e}")

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
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:5173", "http://127.0.0.1:8080","https://vulnscan-nine.vercel.app"],  # Vite default ports
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

# Convenience endpoint to fetch current in-memory vulnerabilities including ai_summary/remediation (frontend AIAnalysis relies on /api/vulnerabilities but may cache)
@app.get("/api/ai/current")
async def get_current_ai_state():
    # Ensure each vulnerability has a unique id and ai_summary is a string
    def normalize_vuln(v, idx):
        v = dict(v)
        v["id"] = v.get("id") or str(idx)
        if v.get("ai_summary") is None:
            v["ai_summary"] = ""
        else:
            v["ai_summary"] = str(v["ai_summary"])
        return v
    vulns = [normalize_vuln(v, i) for i, v in enumerate(scan_state.vulnerabilities)]
    return {
        "vulnerabilities": vulns,
        "total": len(vulns),
        "timestamp": datetime.utcnow().isoformat()
    }

# ==================== REPORT GENERATION FUNCTIONS ====================

def generate_html_report(scan, vulnerabilities, logs, include_ai_analysis=True):
    """Generate a detailed HTML report with AI analysis"""
    from datetime import datetime
    
    # Count vulnerabilities by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    ai_enriched_count = 0
    
    for vuln in vulnerabilities:
        # Handle both dict and Pydantic model formats
        if hasattr(vuln, 'severity'):
            severity = getattr(vuln, 'severity', 'medium').lower()
        else:
            severity = vuln.get('severity', 'medium').lower()
        
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Check if vulnerability has AI analysis
        if hasattr(vuln, 'ai_summary'):
            ai_summary = getattr(vuln, 'ai_summary', None)
            remediation = getattr(vuln, 'remediation', None)
        else:
            ai_summary = vuln.get('ai_summary')
            remediation = vuln.get('remediation')
            
        if ai_summary or (remediation and len(str(remediation or '')) > 50):
            ai_enriched_count += 1
    
    # Generate vulnerability details
    vuln_details = ""
    for i, vuln in enumerate(vulnerabilities, 1):
        # Handle both dict and Pydantic model formats
        if hasattr(vuln, 'ai_summary'):
            ai_summary = getattr(vuln, 'ai_summary', None)
            remediation = getattr(vuln, 'remediation', None)
            severity = getattr(vuln, 'severity', 'medium')
            vuln_type = getattr(vuln, 'type', 'Unknown')
            url = getattr(vuln, 'url', 'N/A')
            parameter = getattr(vuln, 'parameter', None)
            evidence = getattr(vuln, 'evidence', 'No evidence provided')
            payload = getattr(vuln, 'payload', None)
        else:
            ai_summary = vuln.get('ai_summary')
            remediation = vuln.get('remediation')
            severity = vuln.get('severity', 'medium')
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('url', 'N/A')
            parameter = vuln.get('parameter')
            evidence = vuln.get('evidence', 'No evidence provided')
            payload = vuln.get('payload')
        
        ai_badge = ""
        if ai_summary or (remediation and len(str(remediation or '')) > 50):
            ai_badge = '<span class="ai-badge">🤖 AI Enhanced</span>'
        
        vuln_details += f"""
        <div class="vulnerability-item severity-{severity.lower()}">
            <h4>#{i}. {vuln_type.upper()} Vulnerability {ai_badge}</h4>
            <div class="vuln-meta">
                <span class="severity severity-{severity.lower()}">{severity.upper()}</span>
                <span class="url">{url}</span>
                {f"<span class='parameter'>Parameter: {parameter}</span>" if parameter else ""}
            </div>
            <div class="evidence">
                <strong>Evidence:</strong> {evidence[:500]}{'...' if len(str(evidence)) > 500 else ''}
            </div>
            {f"<div class='payload'><strong>Payload:</strong> <code>{payload}</code></div>" if payload else ""}
            {f"<div class='ai-analysis'><strong>🤖 AI Remediation:</strong> {remediation}</div>" if include_ai_analysis and remediation else ""}
        </div>
        """
    
    # Generate scan logs
    log_entries = ""
    for log in logs[-50:]:  # Last 50 log entries
        # Handle both dict and Pydantic model formats
        if hasattr(log, 'timestamp'):
            timestamp = getattr(log, 'timestamp', datetime.now()).isoformat()
            level = getattr(log, 'level', 'info')
            message = getattr(log, 'message', '')
        else:
            timestamp = log.get('timestamp', datetime.now().isoformat())
            level = log.get('level', 'info')
            message = log.get('message', '')
        log_entries += f'<div class="log-entry log-{level}">[{timestamp}] {level.upper()}: {message}</div>\n'
    
    # Handle scan object (dict or Pydantic model)
    if hasattr(scan, 'target_url'):
        target_url = getattr(scan, 'target_url', 'Unknown Target')
    else:
        target_url = scan.get('target_url', 'Unknown Target')
    
    # Normalize scan fields (works for dict or Pydantic model)
    try:
        if hasattr(scan, 'scan_id'):
            _scan_id = getattr(scan, 'scan_id', 'N/A')
            _scan_types = list(getattr(scan, 'scan_types', []) or [])
            _mode = getattr(scan, 'mode', 'N/A')
            _status = getattr(scan, 'status', 'N/A')
            _created_at = getattr(scan, 'created_at', 'N/A')
            _duration = getattr(scan, 'total_time', None) or getattr(scan, 'duration', None)
        else:
            _scan_id = scan.get('scan_id', 'N/A')
            _scan_types = list(scan.get('scan_types', []) or [])
            _mode = scan.get('mode', 'N/A')
            _status = scan.get('status', 'N/A')
            _created_at = scan.get('created_at', 'N/A')
            _duration = scan.get('duration', scan.get('total_time', 'N/A'))
        if isinstance(_created_at, datetime):
            _created_at_str = _created_at.strftime('%Y-%m-%d %H:%M:%S')
        else:
            _created_at_str = str(_created_at)[:19]
        if isinstance(_duration, (int, float)):
            duration_str = f"{int(_duration)}s"
        elif _duration is None:
            duration_str = 'N/A'
        else:
            duration_str = str(_duration)
    except Exception:
        _scan_id = 'N/A'
        _scan_types = []
        _mode = 'N/A'
        _status = 'N/A'
        _created_at_str = 'N/A'
        duration_str = 'N/A'

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report - {target_url}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 40px; border-bottom: 3px solid #4f46e5; padding-bottom: 20px; }}
            .header h1 {{ color: #4f46e5; margin: 0; font-size: 2.5rem; }}
            .header p {{ color: #666; font-size: 1.1rem; margin: 10px 0; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
            .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
            .summary-card h3 {{ margin: 0 0 10px 0; font-size: 1.2rem; }}
            .summary-card .number {{ font-size: 2rem; font-weight: bold; }}
            .severity-critical {{ background: linear-gradient(135deg, #dc2626, #ef4444) !important; }}
            .severity-high {{ background: linear-gradient(135deg, #ea580c, #f97316) !important; }}
            .severity-medium {{ background: linear-gradient(135deg, #ca8a04, #eab308) !important; }}
            .severity-low {{ background: linear-gradient(135deg, #16a34a, #22c55e) !important; }}
            .vulnerability-item {{ margin: 20px 0; padding: 20px; border-left: 5px solid #ccc; background: #f9f9f9; border-radius: 5px; }}
            .vulnerability-item.severity-critical {{ border-left-color: #dc2626; background: #fef2f2; }}
            .vulnerability-item.severity-high {{ border-left-color: #ea580c; background: #fff7ed; }}
            .vulnerability-item.severity-medium {{ border-left-color: #ca8a04; background: #fffbeb; }}
            .vulnerability-item.severity-low {{ border-left-color: #16a34a; background: #f0fdf4; }}
            .severity {{ padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8rem; }}
            .severity.severity-critical {{ background: #dc2626; }}
            .severity.severity-high {{ background: #ea580c; }}
            .severity.severity-medium {{ background: #ca8a04; }}
            .severity.severity-low {{ background: #16a34a; }}
            .ai-badge {{ background: linear-gradient(135deg, #8b5cf6, #a855f7); color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; margin-left: 10px; }}
            .ai-analysis {{ background: #f3f4f6; padding: 15px; border-radius: 8px; margin-top: 10px; border-left: 4px solid #8b5cf6; }}
            .vuln-meta {{ margin: 10px 0; }}
            .vuln-meta span {{ margin-right: 15px; display: inline-block; }}
            .url {{ color: #4f46e5; }}
            .parameter {{ background: #e5e7eb; padding: 2px 6px; border-radius: 3px; }}
            .evidence {{ margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }}
            .payload {{ margin: 10px 0; }}
            .payload code {{ background: #1f2937; color: #f9fafb; padding: 5px 8px; border-radius: 4px; }}
            .section {{ margin: 40px 0; }}
            .section h2 {{ color: #4f46e5; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
            .log-entries {{ max-height: 400px; overflow-y: auto; background: #1f2937; padding: 15px; border-radius: 8px; }}
            .log-entry {{ color: #f9fafb; font-family: 'Courier New', monospace; margin: 2px 0; font-size: 0.9rem; }}
            .log-error {{ color: #fca5a5; }}
            .log-warning {{ color: #fcd34d; }}
            .log-info {{ color: #93c5fd; }}
            .scan-info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
            .info-item {{ background: #f8f9fa; padding: 15px; border-radius: 8px; }}
            .info-item strong {{ color: #4f46e5; }}
            .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Security Scan Report</h1>
                <p><strong>Target:</strong> {target_url}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            
            <div class="summary">
                <div class="summary-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="number">{len(vulnerabilities)}</div>
                </div>
                <div class="summary-card severity-critical">
                    <h3>Critical</h3>
                    <div class="number">{severity_counts['critical']}</div>
                </div>
                <div class="summary-card severity-high">
                    <h3>High</h3>
                    <div class="number">{severity_counts['high']}</div>
                </div>
                <div class="summary-card severity-medium">
                    <h3>Medium</h3>
                    <div class="number">{severity_counts['medium']}</div>
                </div>
                <div class="summary-card severity-low">
                    <h3>Low</h3>
                    <div class="number">{severity_counts['low']}</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #8b5cf6, #a855f7);">
                    <h3>🤖 AI Enhanced</h3>
                    <div class="number">{ai_enriched_count}</div>
                </div>
            </div>
            
            <div class="scan-info">
                <div class="info-item">
                    <strong>Scan ID:</strong> {_scan_id}
                </div>
                <div class="info-item">
                    <strong>Scan Types:</strong> {', '.join(_scan_types)}
                </div>
                <div class="info-item">
                    <strong>Mode:</strong> {str(_mode).title()}
                </div>
                <div class="info-item">
                    <strong>Status:</strong> {str(_status).title()}
                </div>
                <div class="info-item">
                    <strong>Duration:</strong> {duration_str}
                </div>
                <div class="info-item">
                    <strong>Started:</strong> {_created_at_str}
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Vulnerability Details</h2>
                {vuln_details if vulnerabilities else '<p>No vulnerabilities found.</p>'}
            </div>
            
            <div class="section">
                <h2>📋 Scan Logs</h2>
                <div class="log-entries">
                    {log_entries if logs else '<div class="log-entry">No logs available.</div>'}
                </div>
            </div>
            
            <div class="footer">
                <p>Generated by VulnScan Security Scanner | Report includes AI-enhanced vulnerability analysis</p>
                <p>⚡ Scanned {len(vulnerabilities)} vulnerabilities • 🤖 {ai_enriched_count} AI-enhanced findings</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_content

def generate_pdf_report(scan, vulnerabilities, logs, include_ai_analysis=True):
    """Generate a PDF report (requires reportlab)"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from io import BytesIO
        import base64
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#4f46e5'),
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=12,
            textColor=colors.HexColor('#4f46e5')
        )
        
        # Build document content
        story = []
        
        # Handle scan object (dict or Pydantic model)
        if hasattr(scan, 'target_url'):
            target_url = getattr(scan, 'target_url', 'Unknown')
        else:
            target_url = scan.get('target_url', 'Unknown')
        
        # Title
        story.append(Paragraph("🛡️ Security Scan Report", title_style))
        story.append(Paragraph(f"<b>Target:</b> {target_url}", styles['Normal']))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("📊 Executive Summary", heading_style))
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        ai_enriched_count = 0
        
        for vuln in vulnerabilities:
            # Handle both dict and Pydantic model formats
            if hasattr(vuln, 'severity'):
                severity = getattr(vuln, 'severity', 'medium').lower()
                ai_summary = getattr(vuln, 'ai_summary', None)
                remediation = getattr(vuln, 'remediation', None)
            else:
                severity = vuln.get('severity', 'medium').lower()
                ai_summary = vuln.get('ai_summary')
                remediation = vuln.get('remediation')
                
            if severity in severity_counts:
                severity_counts[severity] += 1
            if ai_summary or (remediation and len(str(remediation or '')) > 50):
                ai_enriched_count += 1
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Vulnerabilities', str(len(vulnerabilities))],
            ['Critical Severity', str(severity_counts['critical'])],
            ['High Severity', str(severity_counts['high'])],
            ['Medium Severity', str(severity_counts['medium'])],
            ['Low Severity', str(severity_counts['low'])],
            ['🤖 AI Enhanced', str(ai_enriched_count)]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4f46e5')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Scan Information
        story.append(Paragraph("ℹ️ Scan Information", heading_style))
        
        # Handle scan object for scan info
        if hasattr(scan, 'scan_id'):
            scan_id = getattr(scan, 'scan_id', 'N/A')
            scan_types = getattr(scan, 'scan_types', [])
            mode = getattr(scan, 'mode', 'N/A')
            status = getattr(scan, 'status', 'N/A')
            created_at = getattr(scan, 'created_at', 'N/A')
        else:
            scan_id = scan.get('scan_id', 'N/A')
            scan_types = scan.get('scan_types', [])
            mode = scan.get('mode', 'N/A')
            status = scan.get('status', 'N/A')
            created_at = scan.get('created_at', 'N/A')
        
        scan_info_data = [
            ['Scan ID', scan_id],
            ['Scan Types', ', '.join(scan_types)],
            ['Mode', str(mode).title()],
            ['Status', str(status).title()],
            ['Started', str(created_at)[:19]]
        ]
        
        for label, value in scan_info_data:
            story.append(Paragraph(f"<b>{label}:</b> {value}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Vulnerabilities
        if vulnerabilities:
            story.append(Paragraph("🔍 Vulnerability Details", heading_style))
            
            for i, vuln in enumerate(vulnerabilities, 1):
                # Handle both dict and Pydantic model formats
                if hasattr(vuln, 'ai_summary'):
                    ai_summary = getattr(vuln, 'ai_summary', None)
                    remediation = getattr(vuln, 'remediation', None)
                    vuln_type = getattr(vuln, 'type', 'Unknown')
                    severity = getattr(vuln, 'severity', 'Medium')
                    url = getattr(vuln, 'url', 'N/A')
                    parameter = getattr(vuln, 'parameter', None)
                    evidence = getattr(vuln, 'evidence', 'No evidence provided')
                    payload = getattr(vuln, 'payload', None)
                else:
                    ai_summary = vuln.get('ai_summary')
                    remediation = vuln.get('remediation')
                    vuln_type = vuln.get('type', 'Unknown')
                    severity = vuln.get('severity', 'Medium')
                    url = vuln.get('url', 'N/A')
                    parameter = vuln.get('parameter')
                    evidence = vuln.get('evidence', 'No evidence provided')
                    payload = vuln.get('payload')
                
                ai_indicator = "🤖 " if (ai_summary or (remediation and len(str(remediation or '')) > 50)) else ""
                
                story.append(Paragraph(f"<b>#{i}. {ai_indicator}{vuln_type.upper()} - {severity.upper()}</b>", styles['Heading3']))
                story.append(Paragraph(f"<b>URL:</b> {url}", styles['Normal']))
                
                if parameter:
                    story.append(Paragraph(f"<b>Parameter:</b> {parameter}", styles['Normal']))
                
                if len(str(evidence)) > 300:
                    evidence = str(evidence)[:300] + "..."
                story.append(Paragraph(f"<b>Evidence:</b> {evidence}", styles['Normal']))
                
                if payload:
                    story.append(Paragraph(f"<b>Payload:</b> <font name='Courier'>{payload}</font>", styles['Normal']))
                
                if include_ai_analysis and remediation:
                    story.append(Paragraph(f"<b>🤖 AI Remediation:</b> {remediation}", styles['Normal']))
                
                story.append(Spacer(1, 15))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
        
    except ImportError:
        # Fallback to HTML if reportlab is not available
        raise HTTPException(status_code=500, detail="PDF generation requires reportlab package. Install with: pip install reportlab")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

# Pydantic models for API requests
class ScanRequest(BaseModel):
    target_url: str
    # Extend default scan types to include new categories
    scan_types: List[str] = [
        "xss", "sqli", "csrf",
        "broken_access_control",
        "cryptographic_failures",
        "authentication_failures",
        "integrity_failures",
        "logging_monitoring_failures"
    ]
    mode: str = "fast"  # fast or full
    headless: bool = False
    oast: bool = False
    ai_calls: int = 0
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
    type: str  # plain string to support new dynamic categories
    url: str
    parameter: str
    payload: str
    evidence: str
    remediation: str
    cvss: float
    epss: float
    severity: str  # plain string now
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
            enable_oast=scan_request.oast,
            headless=scan_request.headless,
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
            # Persist scan and vulnerabilities to MongoDB
            if mongodb.is_connected():
                from models import VulnerabilityDocument
                for v in scan_state.vulnerabilities:
                    try:
                        vdoc = VulnerabilityDocument(
                            scan_id=scan_id,
                            type=v.get("type", "unknown"),
                            url=v.get("url", ""),
                            parameter=v.get("parameter"),
                            payload=v.get("payload"),
                            evidence=v.get("evidence", ""),
                            severity=v.get("severity", "medium"),
                            cvss_score=v.get("cvss", 0.0),
                            epss_score=v.get("epss", 0.0),
                            confidence=v.get("confidence", "Medium"),
                            remediation=v.get("remediation"),
                            ai_summary=v.get("ai_summary"),
                        )
                        await mongo_service.create_vulnerability(vdoc)
                    except Exception as e:
                        print(f"Failed to persist vulnerability: {e}")
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
    return {"message": "VulnScan GUI API Server", "status": "running", "version": "1.0.0"}

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
        # Ensure minimum backfill if empty
        await mongo_service.ensure_minimum_analytics(days=days)

        result = await mongo_service.get_analytics(days=days)
        if not result:
            return {"daily_data": [], "total_scans": 0, "vulnerability_trends": {}, "scan_success_rate": 0, "date_range": ""}
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

@app.post("/api/analytics/rebuild")
async def rebuild_analytics(days: int = 90):
    """Recompute analytics documents for the past N days (default 90). Useful after adding new vuln categories."""
    try:
        from datetime import timedelta, datetime as dt
        rebuilt = []
        for i in range(days):
            date = (dt.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            await mongo_service.update_analytics(date)
            rebuilt.append(date)
        return {"status": "success", "rebuilt_days": len(rebuilt), "days": rebuilt[:10] + (["..."] if len(rebuilt) > 10 else [])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rebuild analytics: {str(e)}")

@app.post("/api/analytics/force_rebuild")
async def force_rebuild_analytics(days: int = 90):
    """Force rebuild analytics using the new mongo_service.force_rebuild helper."""
    try:
        result = await mongo_service.force_rebuild(days=days)
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to force rebuild analytics: {str(e)}")

@app.post("/api/analytics/refresh_for_scan/{scan_id}")
async def refresh_analytics_for_scan(scan_id: str):
    """Convenience endpoint: determine the scan's date and update that day's analytics."""
    try:
        if not mongodb.is_connected():
            raise HTTPException(status_code=400, detail="MongoDB not connected")
        from database import mongodb as _mdb
        scan_doc = await _mdb.db.scans.find_one({"scan_id": scan_id})
        if not scan_doc:
            raise HTTPException(status_code=404, detail="Scan not found")
        date = scan_doc.get("created_at")
        if date:
            try:
                date_str = date.strftime("%Y-%m-%d")
            except Exception:
                # if already string
                date_str = str(date)[:10]
        else:
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
        await mongo_service.update_analytics(date_str)
        return {"status": "success", "message": f"Analytics refreshed for {date_str}", "scan_id": scan_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to refresh analytics for scan: {str(e)}")

# ==================== REPORT GENERATION ENDPOINTS ====================

@app.get("/api/scan/{scan_id}/report")
async def download_scan_report(
    scan_id: str,
    format: str = "html",
    include_ai_analysis: bool = True
):
    """Generate and download a detailed scan report in HTML or PDF format"""
    try:
        # Get scan details
        scan = await mongo_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities for this scan
        vulns_response = await mongo_service.get_vulnerabilities(scan_id=scan_id)
        vulnerabilities = vulns_response.get("vulnerabilities", [])
        
        # Get scan logs
        logs = await mongo_service.get_scan_logs(scan_id)
        
        # Generate report content
        if format.lower() == "html":
            report_content = generate_html_report(scan, vulnerabilities, logs, include_ai_analysis)
            return Response(
                content=report_content,
                media_type="text/html",
                headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.html"}
            )
        elif format.lower() == "pdf":
            pdf_content = generate_pdf_report(scan, vulnerabilities, logs, include_ai_analysis)
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"}
            )
        else:
            raise HTTPException(status_code=400, detail="Supported formats: html, pdf")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

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
    # Try to get all vulnerabilities from MongoDB first (for historical data)
    try:
        # Get all vulnerabilities from MongoDB (not just latest scan)
        mongo_response = await mongo_service.get_vulnerabilities()  # Get all vulnerabilities
        
        if mongo_response and mongo_response.get("vulnerabilities"):
            mongo_vulns = mongo_response["vulnerabilities"]
            # Build dynamic counts by vulnerability type
            by_type: Dict[str, int] = {}
            for v in mongo_vulns:
                try:
                    # Handle both dict and object formats
                    if hasattr(v, 'type'):
                        t = str(v.type).lower()
                    else:
                        t = str(v.get("type", "unknown")).lower()
                except Exception:
                    t = "unknown"
                by_type[t] = by_type.get(t, 0) + 1
            
            return {
                "vulnerabilities": mongo_vulns,
                "total": len(mongo_vulns),
                "by_type": by_type,
            }
    except Exception as e:
        print(f"Error fetching from MongoDB: {e}")
        # Fall back to in-memory cache

    # Fallback to in-memory cache
    def normalize_vuln(v, idx):
        v = dict(v)
        v["id"] = v.get("id") or str(idx)
        if v.get("ai_summary") is None:
            v["ai_summary"] = ""
        else:
            v["ai_summary"] = str(v["ai_summary"])
        return v
    vulns = [normalize_vuln(v, i) for i, v in enumerate(scan_state.vulnerabilities)]
    by_type: Dict[str, int] = {}
    for v in vulns:
        try:
            t = str(v.get("type", "unknown")).lower()
        except Exception:
            t = "unknown"
        by_type[t] = by_type.get(t, 0) + 1

    return {
        "vulnerabilities": vulns,
        "total": len(vulns),
        "by_type": by_type,
    }

@app.get("/api/ai/status")
async def get_ai_status():
    """Get AI enrichment status and configuration"""
    try:
        api_key = os.getenv("GROQ_API_KEY")
        return {
            "api_key_set": bool(api_key),
            "api_key_length": len(api_key) if api_key else 0,
            "groq_model": os.getenv("GROQ_MODEL", "qwen/qwen3-32b"),
            "groq_available": True,
            "status": "ready" if api_key else "missing_api_key"
        }
    except Exception as e:
        return {
            "api_key_set": False,
            "error": str(e),
            "groq_available": False,
            "status": "error"
        }

@app.post("/api/ai/enrich")
async def enrich_vulnerabilities():
    if scan_state.vulnerabilities is None:
        scan_state.vulnerabilities = []
    if not scan_state.vulnerabilities:
        return {"status": "error", "message": "No vulnerabilities to enrich"}
    
    try:
        add_log_entry("Starting AI enrichment...", "info", None, "enriching")
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            # Provide placeholder remediation if missing
            placeholders_added = 0
            for v in scan_state.vulnerabilities:
                if not v.get("remediation"):
                    v_type = v.get("type", "vulnerability")
                    v["remediation"] = f"AI remediation unavailable (missing GROQ_API_KEY). Apply best practices to mitigate {v_type}."
                    # Mark as not actually AI enriched but provide ai_summary placeholder so coverage logic can reflect attempted enrichment
                    if not v.get("ai_summary"):
                        v["ai_summary"] = f"AI skipped ({v_type})"
                    placeholders_added += 1
            add_log_entry(f"GROQ_API_KEY not set; skipped external AI calls (placeholders added: {placeholders_added})", "warning", None, "enriching")
            await manager.send_message({
                "type": "ai_enrichment_skipped",
                "message": "AI enrichment skipped (missing GROQ_API_KEY). Placeholder remediation added where absent.",
                "enriched_count": 0,
                "placeholders_added": placeholders_added
            })
            return {"status": "skipped", "message": "AI enrichment skipped (missing GROQ_API_KEY)."}

        # Convert dict back to finding objects for AI enrichment
        class MockFinding:
            def __init__(self, vuln_dict):
                self.vulnerability_type = vuln_dict.get("type", "unknown")
                self.url = vuln_dict.get("url", "")
                self.parameter = vuln_dict.get("parameter", "")
                self.payload = vuln_dict.get("payload", "")
                self.evidence = vuln_dict.get("evidence", "")
                self.confidence = vuln_dict.get("confidence", "Medium")
                self.remediation = vuln_dict.get("remediation", "")

        mock_findings = [MockFinding(v) for v in scan_state.vulnerabilities]
        enriched_findings = groq_ai_enrich(mock_findings)

        # Update stored vulnerabilities with (possibly improved) remediation text
        updated = 0
        for i, finding in enumerate(enriched_findings):
            if i >= len(scan_state.vulnerabilities):
                break  # Safety check
            
            changed = False
            if hasattr(finding, 'remediation') and finding.remediation:
                scan_state.vulnerabilities[i]["remediation"] = finding.remediation
                changed = True
            
            # Always set ai_summary if enrichment ran, even if remediation unchanged
            vuln_type = scan_state.vulnerabilities[i].get("type", "vulnerability")
            if hasattr(finding, 'ai_summary') and getattr(finding, 'ai_summary'):
                scan_state.vulnerabilities[i]["ai_summary"] = finding.ai_summary
            else:
                if not scan_state.vulnerabilities[i].get("ai_summary"):
                    scan_state.vulnerabilities[i]["ai_summary"] = f"AI-enhanced {vuln_type} remediation"
            if changed:
                updated += 1

        # Persist enriched vulnerabilities to MongoDB
        if mongodb.is_connected() and scan_state.current_scan_id:
            from models import VulnerabilityDocument
            for v in scan_state.vulnerabilities:
                try:
                    vdoc = VulnerabilityDocument(
                        scan_id=scan_state.current_scan_id,
                        type=v.get("type", "unknown"),
                        url=v.get("url", ""),
                        parameter=v.get("parameter"),
                        payload=v.get("payload"),
                        evidence=v.get("evidence", ""),
                        severity=v.get("severity", "medium"),
                        cvss_score=v.get("cvss", 0.0),
                        epss_score=v.get("epss", 0.0),
                        confidence=v.get("confidence", "Medium"),
                        remediation=v.get("remediation"),
                        ai_summary=v.get("ai_summary"),
                    )
                    await mongo_service.create_vulnerability(vdoc)
                except Exception as e:
                    print(f"Failed to persist enriched vulnerability: {e}")

        add_log_entry("AI enrichment completed", "info", None, "enriching")
        await manager.send_message({
            "type": "ai_enrichment_complete",
            "message": "AI remediation enrichment completed",
            "enriched_count": updated
        })
        return {"status": "success", "message": "AI remediation enrichment completed", "enriched_count": updated}
    except Exception as e:
        add_log_entry(f"AI enrichment failed: {str(e)}", "error", None, "enriching")
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

@app.post("/api/oast/simulate")
async def simulate_oast_callback(payload_id: str, vulnerability_type: Optional[str] = None):
    """Simulate an OAST callback for testing/demo purposes.
    This helps verify frontend real-time updates without an actual external collaborator."""
    try:
        payloads = oast_collaborator.payloads
        if payload_id not in payloads:
            raise HTTPException(status_code=404, detail="Payload ID not found")
        payload = payloads[payload_id]
        vuln_type = vulnerability_type or payload.vulnerability_type or "unknown"
        callback_data = {
            "payload_id": payload_id,
            "source_ip": "127.0.0.1",
            "method": "GET",
            "headers": {"X-Demo": "true"},
            "body": "",
            "url": f"{payload.callback_url}?simulated=1",
            "vulnerability_type": vuln_type,
            "scan_id": payload.scan_id
        }
        success = await oast_collaborator.register_callback(callback_data)
        if success:
            await manager.send_message({
                "type": "oast_callback",
                "payload_id": payload_id,
                "source_ip": callback_data["source_ip"],
                "timestamp": datetime.now().isoformat(),
                "vulnerability_type": vuln_type
            })
            return {"status": "success", "message": "Simulated callback registered"}
        raise HTTPException(status_code=500, detail="Failed to register simulated callback")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")

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
    print("Starting VulnScan GUI API Server...")
    print("Backend will be available at: http://localhost:8000")
    print("API docs available at: http://localhost:8000/docs")
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=False)
