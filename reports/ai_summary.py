def generate_ai_summary(findings, target_url):
    """
    Generate a human-friendly AI-style summary of the scan findings.
    This is a rule-based summary for now, but can be upgraded to use LLMs.
    """
    if not findings:
        return f"No vulnerabilities were found on {target_url}. The application appears secure against the tested vulnerabilities."

    vuln_types = {}
    for f in findings:
        vt = f.vulnerability_type.upper()
        vuln_types.setdefault(vt, 0)
        vuln_types[vt] += 1

    summary = [f"Scan Summary for {target_url}:"]
    summary.append(f"Total vulnerabilities found: {len(findings)}.")
    for vt, count in vuln_types.items():
        summary.append(f"- {vt}: {count} instance(s)")

    summary.append("\nRecommendations:")
    if 'SQLI' in vuln_types:
        summary.append("- Review all database queries for proper parameterization to prevent SQL injection.")
    if 'XSS' in vuln_types:
        summary.append("- Sanitize and encode all user input/output to prevent XSS attacks.")
    if 'CSRF' in vuln_types:
        summary.append("- Implement CSRF tokens and verify them on all state-changing requests.")
    summary.append("- Regularly update dependencies and perform security testing.")
    return '\n'.join(summary)
