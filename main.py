import argparse
import sys
import json
import os
from crawler import Crawler
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.csrf_scanner import CSRFScanner
from oast_collaborator import VulnPyCollaborator
from requests import Session
from jinja2 import Environment, FileSystemLoader

def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnPy: Automated Web Vulnerability Scanner (XSS, SQLi, CSRF)"
    )
    parser.add_argument("url", help="The full starting URL of the target web application to scan.")
    parser.add_argument("--scan", "-s", default="xss,sqli,csrf", help="Comma-separated list of vulnerability types to scan for (xss, sqli, csrf). Defaults to all.")
    parser.add_argument("--output", "-o", default="report.html", help="Filename for the generated HTML report. Defaults to report.html.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging to the console.")
    parser.add_argument("--cookie", "-c", help="Session cookie string for authenticated scanning.")
    parser.add_argument("--delay", "-d", type=float, default=0, help="Delay in seconds between HTTP requests.")
    parser.add_argument("--headless", action="store_true", help="Enable headless browser crawling (Playwright, for JS-heavy sites and SPAs).")
    parser.add_argument("--oast", action="store_true", help="Enable Out-of-Band Application Security Testing (OAST) for blind vulnerability detection.")
    return parser.parse_args()

def generate_report(findings, target_url, output_file):
    # Use absolute path for the template directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(base_dir, 'reports')
    env = Environment(loader=FileSystemLoader(template_dir))
    from reports.ai_summary import generate_ai_summary
    ai_summary = generate_ai_summary(findings, target_url)
    template = env.get_template('template.html')
    html = template.render(findings=findings, target_url=target_url, ai_summary=ai_summary)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"\n[+] HTML report generated: {output_file}")

def main():
    args = parse_args()
    print(r"""
                       ooooooooo.               ooooooooo.
                        `888                   `888   `Y88.             
oooo    ooo oooo  oooo   888  ooo. .oo.         888   .d88' oooo    ooo 
 `88.  .8'  `888  `888   888  `888P"Y88b        888ooo88P'   `88.  .8'  
  `88..8'    888   888   888   888   888        888           `88..8'   
   `888'     888   888   888   888   888        888            `888'    
    `8'      `V88V"V8P' o888o o888o o888o      o888o            .8'     
                                                            .o..P'      
                                                            `Y8P'       
                                                                         
    """)
    crawler = Crawler(
        base_url=args.url,
        cookie=args.cookie,
        delay=args.delay,
        verbose=args.verbose,
        max_depth=5,   # Increased crawl depth
        max_pages=100,  # Increased max pages
        use_browser=args.headless
    )
    attack_surface = crawler.crawl()
    print("\nAttack Surface Map:")
    print("Discovered URLs with parameters:")
    for url, params in attack_surface['urls']:
        print(f"  {url} | Params: {params}")
    print("\nDiscovered Forms:")
    for form in attack_surface['forms']:
        print(f"  {form}")

    # Run all scanners
    import json, os
    from scanners.sqli_scanner import SQLiScanner
    from scanners.xss_scanner import XSSScanner
    from scanners.csrf_scanner import CSRFScanner
    
    # Initialize OAST collaborator if enabled
    oast_collaborator = None
    if args.oast:
        print("[+] Initializing OAST Collaborator for blind vulnerability detection...")
        try:
            oast_collaborator = VulnPyCollaborator()
            oast_collaborator.start()
            print(f"[+] OAST Collaborator started on {oast_collaborator.domain}:{oast_collaborator.http_port}")
        except Exception as e:
            print(f"[!] Failed to start OAST Collaborator: {e}")
            print("[!] Continuing without OAST support...")
            oast_collaborator = None
    
    # Robust path resolution for payloads
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sqli_payloads_path = os.path.join(base_dir, 'payloads', 'sqli_payloads.json')
    with open(sqli_payloads_path, 'r', encoding='utf-8') as f:
        sqli_payloads = json.load(f)
    xss_payloads_path = os.path.join(base_dir, 'payloads', 'xss_payloads.txt')
    with open(xss_payloads_path, 'r', encoding='utf-8') as f:
        xss_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    # Initialize scanners with OAST support
    sqli_scanner = SQLiScanner(crawler.session, sqli_payloads, verbose=args.verbose, oast_collaborator=oast_collaborator)
    xss_scanner = XSSScanner(crawler.session, xss_payloads, verbose=args.verbose, oast_collaborator=oast_collaborator)
    csrf_scanner = CSRFScanner(crawler.session, verbose=args.verbose)
    sqli_findings = sqli_scanner.scan(attack_surface)
    xss_findings = xss_scanner.scan(attack_surface)
    csrf_findings = csrf_scanner.scan(attack_surface)
    all_findings = sqli_findings + xss_findings + csrf_findings
    # Print findings
    print("\nSQLi Findings:")
    for finding in sqli_findings:
        confidence_str = f" (Confidence: {finding.confidence})" if hasattr(finding, 'confidence') and finding.confidence else ""
        print(f"Type: {finding.vulnerability_type}{confidence_str}, URL: {finding.url}, Param: {finding.parameter}, Payload: {finding.payload}\nEvidence: {finding.evidence}\n")
    print("\nXSS Findings:")
    for finding in xss_findings:
        confidence_str = f" (Confidence: {finding.confidence})" if hasattr(finding, 'confidence') and finding.confidence else ""
        print(f"Type: {finding.vulnerability_type}{confidence_str}, URL: {finding.url}, Param: {finding.parameter}, Payload: {finding.payload}\nEvidence: {finding.evidence}\n")
    print("\nCSRF Findings:")
    for finding in csrf_findings:
        confidence_str = f" (Confidence: {finding.confidence})" if hasattr(finding, 'confidence') and finding.confidence else ""
        print(f"Type: {finding.vulnerability_type}{confidence_str}, URL: {finding.url}, Param: {finding.parameter}\nEvidence: {finding.evidence}\n")
    
    # Stop OAST collaborator if it was started
    if oast_collaborator:
        print("\n[+] Stopping OAST Collaborator...")
        oast_collaborator.stop()
        stats = oast_collaborator.get_stats()
        if stats:
            print(f"[+] OAST Statistics: {stats.get('total_callbacks', 0)} callbacks received")
        else:
            print("[+] OAST Statistics: 0 callbacks received")
    
    # Generate HTML report
    generate_report(all_findings, args.url, args.output)

if __name__ == "__main__":
    main()
