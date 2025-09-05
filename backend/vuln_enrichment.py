"""
vuln_enrichment.py
Provides enrichment (remediation, CVSS, EPSS, AI summary) for vulnerabilities using Groq AI

- Reads API key from environment variable GROQ_API_KEY (secure). Falls back to provided key if missing.
- Uses model qwen/qwen3-32b by default (override via GROQ_MODEL).
- Enforces practical rate-limiting: <= 60 req/min and <= 6000 tokens/min.
- Keeps responses concise (max_tokens default 600) and caches by vuln type+param to avoid duplicate calls.
"""
import os
import time
import hashlib
from groq import Groq
import json

# Static vulnerability database with CVSS and EPSS scores
VULN_MAP = {
    'xss': {'cvss': 6.1, 'epss': 0.85, 'severity': 'medium'},
    'sqli': {'cvss': 9.8, 'epss': 0.92, 'severity': 'critical'},
    'csrf': {'cvss': 6.8, 'epss': 0.77, 'severity': 'medium'},
    'ssrf': {'cvss': 8.6, 'epss': 0.81, 'severity': 'high'},
    'security_misconfiguration': {'cvss': 7.5, 'epss': 0.5, 'severity': 'medium'},
    'vulnerable_components': {'cvss': 7.8, 'epss': 0.65, 'severity': 'high'},
}

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
MAX_CALLS_PER_RUN_DEFAULT = int(os.getenv("GROQ_MAX_CALLS_PER_RUN", "50"))

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
    """Enrich a finding with static vulnerability data"""
    vuln_type = finding.vulnerability_type
    if vuln_type in VULN_MAP:
        vuln_data = VULN_MAP[vuln_type]
        finding.cvss = vuln_data['cvss']
        finding.epss = vuln_data['epss']
        finding.severity = vuln_data['severity']
        
        # Add basic remediation advice
        if vuln_type == 'xss':
            finding.remediation = "Implement proper input validation and output encoding. Use Content Security Policy (CSP)."
        elif vuln_type == 'sqli':
            finding.remediation = "Use parameterized queries/prepared statements. Implement input validation and least privilege database access."
        elif vuln_type == 'csrf':
            finding.remediation = "Implement anti-CSRF tokens, SameSite cookie attributes, and proper referrer validation."
    else:
        finding.cvss = 0
        finding.epss = 0
        finding.severity = 'unknown'
        finding.remediation = 'Review and implement security best practices.'

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

def groq_ai_enrich(findings, max_ai_calls=30):
    """
    Enrich findings using Groq AI with intelligent rate limiting and prioritization
    
    Args:
        findings: List of vulnerability findings
        max_ai_calls: Maximum number of AI API calls to make (default: 30)
    """
    if not findings:
        return findings
    
    print(f"[+] Processing {len(findings)} findings with AI enrichment (max {max_ai_calls} AI calls)")
    
    # Set up Groq client with API key
    client = Groq(api_key=GROQ_API_KEY)
    enriched_count = 0
    api_calls_made = 0
    
    # Sort findings by priority (most important first)
    prioritized_findings = sorted(findings, key=get_vulnerability_priority, reverse=True)

    # Clamp per-run API calls to a safe upper bound
    max_allowed_calls = min(max_ai_calls or MAX_CALLS_PER_RUN_DEFAULT, MAX_CALLS_PER_RUN_DEFAULT)
    
    # Process findings with intelligent caching and rate limiting
    for i, finding in enumerate(prioritized_findings):
        try:
            # Check cache first
            cache_key = create_cache_key(finding)
            if cache_key in AI_CACHE:
                cached_result = AI_CACHE[cache_key]
                finding.ai_summary = cached_result.get('summary', 'AI analysis (cached)')
                # Only override remediation if it's basic or doesn't exist
                if not hasattr(finding, 'remediation') or not finding.remediation or 'best practices' in str(finding.remediation):
                    finding.remediation = cached_result.get('remediation', getattr(finding, 'remediation', 'No remediation available'))
                enriched_count += 1
                continue
            
            # Stop making API calls if we've reached the limit
            if api_calls_made >= max_allowed_calls:
                finding.ai_summary = f"AI analysis skipped (rate limit reached, {api_calls_made}/{max_ai_calls} calls used)"
                continue
            
            # Rate limiting: budget checks (daily + per-minute)
            tokens_needed = MAX_TOKENS_PER_CALL + PROMPT_OVERHEAD_TOKENS
            if not _check_and_consume_daily_budget(tokens_needed):
                finding.ai_summary = (
                    f"AI analysis skipped (daily budget reached: calls/tokens limit)"
                )
                continue
            _wait_for_budget(tokens_needed)
            if api_calls_made > 0 and MIN_DELAY_SECONDS > 0:
                time.sleep(MIN_DELAY_SECONDS)
            
            # Create a concise prompt for the finding
            prompt = (
                f"Analyze this web vulnerability:\n"
                f"Type: {finding.vulnerability_type}\n"
                f"URL: {finding.url}\n"
                f"Parameter: {finding.parameter}\n\n"
                f"Provide a JSON response with:\n"
                f"- summary: Brief technical description (1-2 sentences)\n"
                f"- remediation: Specific fix steps\n\n"
                f"Format: {{'summary': '...', 'remediation': '...'}}"
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
                
                # Parse JSON response
                import json
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    try:
                        ai_result = json.loads(json_match.group())
                        finding.ai_summary = ai_result.get('summary', 'AI analysis complete')
                        
                        # Cache the result for similar vulnerabilities
                        AI_CACHE[cache_key] = {
                            'summary': ai_result.get('summary', 'AI analysis complete'),
                            'remediation': ai_result.get('remediation', '')
                        }
                        
                        # Only override remediation if it's empty or basic
                        if not hasattr(finding, 'remediation') or 'best practices' in finding.remediation:
                            finding.remediation = ai_result.get('remediation', finding.remediation)
                        enriched_count += 1
                    except json.JSONDecodeError:
                        # Fallback: use raw response as summary
                        finding.ai_summary = f"AI analysis: {response_text[:150]}..."
                        enriched_count += 1
                else:
                    # Fallback: use raw response as summary  
                    finding.ai_summary = f"AI analysis: {response_text[:150]}..."
                    enriched_count += 1
            else:
                finding.ai_summary = 'No AI response available'
            
            # Progress indicator for large scans
            if len(findings) > 20 and (i + 1) % 10 == 0:
                print(f"[+] AI enrichment progress: {i + 1}/{len(findings)} processed, {api_calls_made} API calls made")
                
        except Exception as e:
            error_msg = str(e)
            print(f"[!] Groq AI error for {getattr(finding, 'url', 'unknown URL')}: {error_msg}")
            
            # Handle specific error types
            if "rate limit" in error_msg.lower() or "too many requests" in error_msg.lower():
                print(f"[!] Rate limit hit after {api_calls_made} calls. Continuing with static enrichment...")
                finding.ai_summary = f'AI rate limit reached (used {api_calls_made} calls)'
                # Stop making more API calls
                max_allowed_calls = api_calls_made
            elif "has no attribute" in error_msg:
                # Attribute error - likely missing field on finding object
                print(f"[!] Attribute error during AI enrichment: {error_msg}")
                finding.ai_summary = 'AI enrichment failed: missing attributes'
            else:
                finding.ai_summary = f'AI enrichment error: {error_msg[:50]}...'
    
    print(f"[+] AI enrichment completed: {enriched_count}/{len(findings)} findings enriched, {api_calls_made} API calls made")
    return findings
