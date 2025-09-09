"""
vuln_enrichment.py
Provides enrichment (remediation, CVSS, EPSS) for vulnerabilities using Groq AI.

Refactor (Sep 2025):
 - Switched to remediation-only AI output (no verbose summaries). Sets ai_summary for frontend filtering.
 - Added cvss_version = '4.0' to each finding for consistency with CLI tool.
 - Expanded VULN_MAP to include additional OWASP 2021 categories used by CLI.
 - Prompt now enforces STRICT single-key JSON: {"remediation":"..."} (<=160 chars) with no extra commentary.
 - Cache stores only remediation; we overwrite existing remediation only if empty or generic.
 - Maintains existing rate limiting & daily budgeting.
"""
import os
import time
import hashlib
from groq import Groq
import json

# Static vulnerability database with CVSS and EPSS scores
VULN_MAP = {
    # Existing types
    'xss': {'cvss': 6.1, 'epss': 0.85, 'severity': 'medium'},
    'sqli': {'cvss': 9.8, 'epss': 0.92, 'severity': 'critical'},
    'csrf': {'cvss': 6.8, 'epss': 0.77, 'severity': 'medium'},
    'ssrf': {'cvss': 8.6, 'epss': 0.81, 'severity': 'high'},
    'security_misconfiguration': {'cvss': 7.5, 'epss': 0.5, 'severity': 'medium'},
    'vulnerable_components': {'cvss': 7.8, 'epss': 0.65, 'severity': 'high'},
    # New categories aligned with CLI
    'broken_access_control': {'cvss': 9.0, 'epss': 0.60, 'severity': 'critical'},
    'cryptographic_failures': {'cvss': 7.4, 'epss': 0.55, 'severity': 'high'},
    'authentication_failures': {'cvss': 8.2, 'epss': 0.58, 'severity': 'high'},
    'integrity_failures': {'cvss': 7.9, 'epss': 0.52, 'severity': 'high'},
    'logging_monitoring_failures': {'cvss': 5.5, 'epss': 0.30, 'severity': 'medium'},
}

CVSS_VERSION = "4.0"

# Cache for AI responses to avoid duplicate API calls
AI_CACHE = {}

# ---------- AI/RATE LIMIT CONFIG ----------
MODEL_NAME = os.getenv("GROQ_MODEL", "qwen/qwen3-32b")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Provider limits
CALLS_PER_MIN_LIMIT = int(os.getenv("GROQ_CALLS_PER_MIN", "60"))
TOKENS_PER_MIN_LIMIT = int(os.getenv("GROQ_TOKENS_PER_MIN", "6000"))

# Local throttle choices (keep under provider ceilings)
MAX_TOKENS_PER_CALL = int(os.getenv("GROQ_MAX_TOKENS", "600"))  # concise JSON answer
PROMPT_OVERHEAD_TOKENS = int(os.getenv("GROQ_PROMPT_OVERHEAD", "400"))  # rough prompt size estimate
MIN_DELAY_SECONDS = float(os.getenv("GROQ_MIN_DELAY", "1.2"))  # between calls
# MAX_CALLS_PER_RUN_DEFAULT removed - no artificial limits, rate limiting handles requests

# Daily budgets (provider): 1k requests/day, 500k tokens/day
CALLS_PER_DAY_LIMIT = int(os.getenv("GROQ_CALLS_PER_DAY", "1000"))
TOKENS_PER_DAY_LIMIT = int(os.getenv("GROQ_TOKENS_PER_DAY", "500000"))
USAGE_FILE = os.getenv("GROQ_USAGE_FILE", os.path.join(os.path.dirname(__file__), "groq_usage.json"))

# Rolling per-minute counters
_window_start_ts = 0.0
_tokens_used_in_window = 0
_calls_in_window = 0

def _reset_window_if_needed():
    global _window_start_ts, _tokens_used_in_window, _calls_in_window
    now = time.time()
    if _window_start_ts == 0.0 or (now - _window_start_ts) >= 60.0:
        _window_start_ts = now
        _tokens_used_in_window = 0
        _calls_in_window = 0

def _wait_for_budget(tokens_needed: int):
    """Block until both calls/min and tokens/min budgets allow another call."""
    global _tokens_used_in_window, _calls_in_window
    while True:
        _reset_window_if_needed()
        if (
            _calls_in_window < CALLS_PER_MIN_LIMIT
            and (_tokens_used_in_window + tokens_needed) <= TOKENS_PER_MIN_LIMIT
        ):
            return
        # Sleep a short time and re-check; align roughly to minute windows
        time.sleep(0.5)
        _reset_window_if_needed()

def _consume_budget(tokens_used: int):
    global _tokens_used_in_window, _calls_in_window
    _tokens_used_in_window += tokens_used
    _calls_in_window += 1

# ---------- DAILY BUDGET TRACKING ----------
def _load_daily_usage():
    today = time.strftime("%Y-%m-%d")
    try:
        if os.path.exists(USAGE_FILE):
            with open(USAGE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("date") == today:
                    return data
    except Exception:
        pass
    return {"date": today, "calls": 0, "tokens": 0}

def _save_daily_usage(data):
    try:
        with open(USAGE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass

def _check_and_consume_daily_budget(tokens_needed: int) -> bool:
    data = _load_daily_usage()
    if data["calls"] + 1 > CALLS_PER_DAY_LIMIT:
        return False
    if data["tokens"] + tokens_needed > TOKENS_PER_DAY_LIMIT:
        return False
    data["calls"] += 1
    data["tokens"] += tokens_needed
    _save_daily_usage(data)
    return True

def enrich_finding(finding):
    """Enrich a finding with static vulnerability data (adds cvss_version)."""
    vuln_type = finding.vulnerability_type
    if vuln_type in VULN_MAP:
        vuln_data = VULN_MAP[vuln_type]
        finding.cvss = vuln_data['cvss']
        finding.epss = vuln_data['epss']
        finding.severity = vuln_data['severity']
        finding.cvss_version = CVSS_VERSION

        # Basic remediation advice seeds (only if not already set)
        if not getattr(finding, 'remediation', None):
            if vuln_type == 'xss':
                finding.remediation = "Implement input validation + output encoding; consider CSP."
            elif vuln_type == 'sqli':
                finding.remediation = "Use parameterized queries; least-priv DB account; validate inputs."
            elif vuln_type == 'csrf':
                finding.remediation = "Add anti-CSRF tokens; set SameSite=Lax/Strict; verify origin."
            elif vuln_type == 'ssrf':
                finding.remediation = "Validate URLs; whitelist hosts; use internal DNS; disable redirects."
            elif vuln_type == 'broken_access_control':
                finding.remediation = "Implement proper authorization checks; use principle of least privilege."
            elif vuln_type == 'cryptographic_failures':
                finding.remediation = "Use strong encryption; proper key management; secure protocols."
            elif vuln_type == 'authentication_failures':
                finding.remediation = "Implement MFA; strong password policies; secure session management."
            elif vuln_type == 'integrity_failures':
                finding.remediation = "Implement digital signatures; use checksums; validate data integrity."
            elif vuln_type == 'logging_monitoring_failures':
                finding.remediation = "Enable security logging; implement monitoring; set up alerts."
            else:
                finding.remediation = "Review and implement security best practices."
            
    else:
        finding.cvss = 0
        finding.epss = 0
        finding.severity = 'unknown'
        finding.remediation = 'Review and implement security best practices.'
        finding.cvss_version = CVSS_VERSION

def get_vulnerability_priority(finding):
    """Get priority score for AI enrichment (higher = more important)"""
    priority = 0
    
    # Priority by vulnerability type
    if finding.vulnerability_type == 'sqli':
        priority += 10  # Highest priority
    elif finding.vulnerability_type == 'xss':
        priority += 7
    elif finding.vulnerability_type == 'csrf':
        priority += 5
    
    # Boost priority for unique URLs/parameters
    unique_key = f"{finding.vulnerability_type}_{finding.parameter}"
    if unique_key not in AI_CACHE:
        priority += 3
    
    return priority

def create_cache_key(finding):
    """Create a cache key for similar vulnerabilities"""
    # Group similar vulnerabilities to avoid redundant API calls
    key_data = f"{finding.vulnerability_type}_{finding.parameter}"
    return hashlib.md5(key_data.encode()).hexdigest()[:12]

def groq_ai_enrich(findings, max_ai_calls=0):
    """
    Enrich findings using Groq AI with intelligent rate limiting and prioritization
    
    Args:
        findings: List of vulnerability findings
        max_ai_calls: Maximum number of AI API calls to make (0 = unlimited, rate limiting handles requests)
    """
    if not findings:
        return findings
    
    # Check if API key is available
    if not GROQ_API_KEY:
        print("[!] GROQ_API_KEY not set. Skipping AI enrichment.")
        for finding in findings:
            enrich_finding(finding)  # Apply static enrichment only
            if not hasattr(finding, 'ai_summary') or not finding.ai_summary:
                finding.ai_summary = f"AI skipped - {finding.vulnerability_type} (missing API key)"
        return findings
    
    print(f"[+] Processing {len(findings)} findings with AI remediation enrichment (rate limited by API)")
    
    # Set up Groq client with API key
    try:
        client = Groq(api_key=GROQ_API_KEY)
    except Exception as e:
        print(f"[!] Failed to initialize Groq client: {e}")
        for finding in findings:
            enrich_finding(finding)  # Apply static enrichment only
            if not hasattr(finding, 'ai_summary') or not finding.ai_summary:
                finding.ai_summary = f"AI skipped - {finding.vulnerability_type} (client error)"
        return findings
    enriched_count = 0
    api_calls_made = 0
    
    # Sort findings by priority (most important first)
    prioritized_findings = sorted(findings, key=get_vulnerability_priority, reverse=True)

    # Only apply max_ai_calls limit if it's set (> 0)
    if max_ai_calls > 0:
        max_allowed_calls = max_ai_calls
    else:
        max_allowed_calls = len(findings)  # No artificial limit, rate limiting handles requests
    
    # Process findings with intelligent caching and rate limiting
    for i, finding in enumerate(prioritized_findings):
        try:
            # Check cache first
            cache_key = create_cache_key(finding)
            if cache_key in AI_CACHE:
                cached_result = AI_CACHE[cache_key]
                # Only override remediation if it's basic or doesn't exist
                if not hasattr(finding, 'remediation') or not finding.remediation or 'best practices' in str(finding.remediation).lower():
                    finding.remediation = cached_result.get('remediation', getattr(finding, 'remediation', 'No remediation available'))
                # Set ai_summary to indicate AI enrichment (for frontend filtering)
                finding.ai_summary = f"AI-enhanced {finding.vulnerability_type} remediation"
                enriched_count += 1
                continue
            
            # Stop making API calls if we've reached the limit
            if api_calls_made >= max_allowed_calls:
                # Skip AI generation due to per-run cap
                continue
            
            # Rate limiting: budget checks (daily + per-minute)
            tokens_needed = MAX_TOKENS_PER_CALL + PROMPT_OVERHEAD_TOKENS
            if not _check_and_consume_daily_budget(tokens_needed):
                # Daily budget exhausted; skip
                continue
            _wait_for_budget(tokens_needed)
            if api_calls_made > 0 and MIN_DELAY_SECONDS > 0:
                time.sleep(MIN_DELAY_SECONDS)
            
            # Create a concise prompt for the finding
            prompt = (
                "You are an application security assistant. Return ONLY strict JSON object: {\"remediation\":\"<fix>\"}."
                " No markdown, no extra keys, no commentary. Remediation under 160 characters."
                f"\nType: {finding.vulnerability_type}"
                f"\nURL: {getattr(finding, 'url', '')}"
                f"\nParameter: {getattr(finding, 'parameter', '')}"
                f"\nEvidence: {getattr(finding, 'evidence', '')[:160]}"
                "\nFocus on concrete mitigation steps (sanitization pattern, config header, parameterized query, permission model, etc)."
            )
            
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.6,
                max_tokens=MAX_TOKENS_PER_CALL,
                top_p=0.95,
                stream=False,
                stop=None
            )
            
            api_calls_made += 1
            _consume_budget(tokens_needed)
            
            # Extract response
            if completion.choices and len(completion.choices) > 0:
                response_text = completion.choices[0].message.content
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                remediation_text = None
                if json_match:
                    try:
                        ai_obj = json.loads(json_match.group())
                        remediation_text = ai_obj.get('remediation')
                    except Exception:
                        remediation_text = None
                if remediation_text:
                    AI_CACHE[cache_key] = {'remediation': remediation_text}
                    if not getattr(finding, 'remediation', None) or 'best practices' in str(getattr(finding, 'remediation')).lower():
                        finding.remediation = remediation_text
                    # Set ai_summary to indicate AI enrichment (for frontend filtering)
                    finding.ai_summary = f"AI-enhanced {finding.vulnerability_type} remediation"
                    enriched_count += 1
            else:
                # No response choices; keep existing remediation
                pass
            
            # Progress indicator for large scans
            if len(findings) > 20 and (i + 1) % 10 == 0:
                print(f"[+] AI remediation progress: {i + 1}/{len(findings)} processed, {api_calls_made} API calls made")
                
        except Exception as e:
            error_msg = str(e)
            print(f"[!] Groq AI error for {getattr(finding, 'url', 'unknown URL')}: {error_msg}")
            
            # Handle specific error types
            if "rate limit" in error_msg.lower() or "too many requests" in error_msg.lower():
                print(f"[!] Rate limit hit after {api_calls_made} calls. Continuing with static remediation only...")
                # Stop making more API calls
                max_allowed_calls = api_calls_made
            elif "has no attribute" in error_msg:
                # Attribute error - likely missing field on finding object
                print(f"[!] Attribute error during AI enrichment: {error_msg}")
            else:
                # Generic error; keep existing remediation
                pass
    
    print(f"[+] AI remediation enrichment completed: {enriched_count}/{len(findings)} updated, {api_calls_made} API calls made")
    return findings
