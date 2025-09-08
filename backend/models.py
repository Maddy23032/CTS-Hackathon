# models.py
# Pydantic models for MongoDB documents

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    ENRICHING = "enriching"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilityType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    CSRF = "csrf"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    SSRF = "ssrf"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AttackSurfaceItem(BaseModel):
    url: str
    method: str = "GET"
    parameters: List[str] = []
    forms: List[Dict[str, Any]] = []
    headers: Dict[str, str] = {}

class VulnerabilityDocument(BaseModel):
    scan_id: str
    # Accept any string to allow newly added categories without enum update
    type: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: str
    severity: str = "medium"
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    confidence: Optional[str] = None
    remediation: Optional[str] = None
    ai_summary: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ScanLogEntry(BaseModel):
    scan_id: str
    level: str  # INFO, WARNING, ERROR
    message: str
    phase: str  # crawling, scanning, enriching
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Optional[Dict[str, Any]] = None

class ScanDocument(BaseModel):
    scan_id: str
    target_url: str
    scan_types: List[str]
    mode: str = "fast"
    status: ScanStatus = ScanStatus.PENDING
    progress: int = 0
    phase: str = "initializing"
    
    # Scan configuration
    max_depth: int = 3
    max_pages: int = 50
    ai_calls: int = 0
    use_oast: bool = False
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Results
    attack_surface: List[AttackSurfaceItem] = []
    vulnerability_count: Dict[str, int] = {}
    total_vulnerabilities: int = 0
    
    # Metadata
    user_agent: Optional[str] = None
    cookies: Optional[str] = None
    report_url: Optional[str] = None
    
    # Performance metrics
    crawl_time: Optional[float] = None
    scan_time: Optional[float] = None
    total_time: Optional[float] = None

class AnalyticsDocument(BaseModel):
    date: str  # YYYY-MM-DD format
    total_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    vulnerabilities_found: Dict[str, int] = {}  # by type
    severity_distribution: Dict[str, int] = {}  # by severity
    avg_scan_time: Optional[float] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

# Request/Response models for API
class ScanRequest(BaseModel):
    target_url: str
    scan_types: List[str] = ["xss", "sqli", "csrf"]
    mode: str = "fast"
    max_depth: int = 3
    max_pages: int = 50
    ai_calls: int = 0
    use_oast: bool = False
    cookies: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class VulnerabilityResponse(BaseModel):
    vulnerabilities: List[VulnerabilityDocument]
    total: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]

class ScanHistoryResponse(BaseModel):
    scans: List[ScanDocument]
    total: int
    page: int
    per_page: int

class AnalyticsResponse(BaseModel):
    date_range: str
    total_scans: int
    vulnerability_trends: Dict[str, List[Dict[str, Any]]]
    severity_distribution: Dict[str, int]
    top_vulnerabilities: List[Dict[str, Any]]
    scan_success_rate: float
