# vuln_enrichment.py
# Provides enrichment (remediation, CVSS, EPSS, AI summary) for vulnerabilities using Groq AI
import os
from groq import Groq

# Static vulnerability database with CVSS and EPSS scores
VULN_MAP = {
    'XSS': {'cvss': 6.1, 'epss': 0.85, 'severity': 'Medium'},
    'SQLi': {'cvss': 9.8, 'epss': 0.92, 'severity': 'Critical'},
    'CSRF': {'cvss': 6.8, 'epss': 0.77, 'severity': 'Medium'}
}

def enrich_finding(finding):
    """Enrich a finding with static vulnerability data"""
    vuln_type = finding.vulnerability_type
    if vuln_type in VULN_MAP:
        vuln_data = VULN_MAP[vuln_type]
        finding.cvss = vuln_data['cvss']
        finding.epss = vuln_data['epss']
        finding.severity = vuln_data['severity']
        
        # Add basic remediation advice
        if vuln_type == 'XSS':
            finding.remediation = "Implement proper input validation and output encoding. Use Content Security Policy (CSP)."
        elif vuln_type == 'SQLi':
            finding.remediation = "Use parameterized queries/prepared statements. Implement input validation and least privilege database access."
        elif vuln_type == 'CSRF':
            finding.remediation = "Implement anti-CSRF tokens, SameSite cookie attributes, and proper referrer validation."
    else:
        finding.cvss = 0
        finding.epss = 0
        finding.severity = 'Unknown'
        finding.remediation = 'Review and implement security best practices.'

def groq_ai_enrich(findings):
    """Enrich findings using Groq AI"""
    if not findings:
        return findings
    
    # Set up Groq client with API key
    client = Groq(api_key="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")
    enriched_count = 0
    
    # Process one finding at a time to avoid token limits
    for finding in findings:
        try:
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
                model="llama-3.1-70b-versatile",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=512,
                top_p=1,
                stream=False,
                stop=None
            )
            
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
                        # Only override remediation if it's empty or basic
                        if not hasattr(finding, 'remediation') or not finding.remediation or 'best practices' in finding.remediation:
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
                
        except Exception as e:
            print(f"[!] Groq AI error for {finding.url}: {e}")
            finding.ai_summary = f'AI enrichment error: {str(e)[:50]}...'
    
    print(f"[+] AI enriched {enriched_count}/{len(findings)} findings")
    return findings
