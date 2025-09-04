# vuln_enrichment.py
# Provides enrichment (remediation, CVSS, EPSS, AI summary) for vulnerabilities using Groq AI
import os
import time
import hashlib
from groq import Groq

# Static vulnerability database with CVSS and EPSS scores
VULN_MAP = {
    'xss': {'cvss': 6.1, 'epss': 0.85, 'severity': 'medium'},
    'sqli': {'cvss': 9.8, 'epss': 0.92, 'severity': 'critical'},
    'csrf': {'cvss': 6.8, 'epss': 0.77, 'severity': 'medium'}
}

# Cache for AI responses to avoid duplicate API calls
AI_CACHE = {}

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
    client = Groq(api_key="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")
    enriched_count = 0
    api_calls_made = 0
    
    # Sort findings by priority (most important first)
    prioritized_findings = sorted(findings, key=get_vulnerability_priority, reverse=True)
    
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
            if api_calls_made >= max_ai_calls:
                finding.ai_summary = f"AI analysis skipped (rate limit reached, {api_calls_made}/{max_ai_calls} calls used)"
                continue
            
            # Rate limiting: Add delay between API calls
            if api_calls_made > 0:
                time.sleep(2)  # 2 second delay between calls
            
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
                model="qwen/qwen3-32b",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.6,
                max_tokens=4096,
                top_p=0.95,
                stream=False,
                stop=None
            )
            
            api_calls_made += 1
            
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
                max_ai_calls = api_calls_made
            elif "has no attribute" in error_msg:
                # Attribute error - likely missing field on finding object
                print(f"[!] Attribute error during AI enrichment: {error_msg}")
                finding.ai_summary = 'AI enrichment failed: missing attributes'
            else:
                finding.ai_summary = f'AI enrichment error: {error_msg[:50]}...'
    
    print(f"[+] AI enrichment completed: {enriched_count}/{len(findings)} findings enriched, {api_calls_made} API calls made")
    return findings
