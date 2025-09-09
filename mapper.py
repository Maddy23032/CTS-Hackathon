import argparse
import sys
from urllib.parse import urlparse
import time

from core.engine import DiscoveryEngine

def main():
    parser = argparse.ArgumentParser(
        description="A comprehensive, multi-threaded attack surface discovery engine.",
        formatter_class=argparse.RawTextHelpFormatter, # Allows for better formatting in help text
        epilog="""Examples:
  # Basic unauthenticated scan with 10 threads
  python mapper.py http://testphp.vulnweb.com/ --threads 10

  # Authenticated scan to find pages behind a login
  python mapper.py http://zero.webappsecurity.com/ --threads 15 --login-url http://zero.webappsecurity.com/login.html --login-data "user_login=username&user_password=password"
"""
    )
    # --- Main Arguments ---
    parser.add_argument("url", help="The base URL to start discovery from.")
    parser.add_argument("--depth", type=int, default=2, help="Maximum crawl depth. Default is 2.")
    parser.add_argument("-o", "--output", help="Custom output file name. If not provided, a unique name will be generated.")
    
    # --- Threading Argument ---
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads to use. Default is 10.")

    # --- Authentication Arguments ---
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument("--login-url", help="The URL where the login form is submitted.")
    auth_group.add_argument("--login-data", help="The POST data for login (e.g., 'user=admin&pass=123').")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    parsed_url = urlparse(args.url)
    if not parsed_url.scheme:
        base_url = "http://" + args.url
    else:
        base_url = args.url

    if args.output:
        output_filename = args.output
    else:
        domain = parsed_url.netloc.replace('.', '_')
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_filename = f"report_{domain}_{timestamp}.txt"

    try:
        # Pass all the new arguments to your engine
        engine = DiscoveryEngine(
            base_url, 
            max_depth=args.depth,
            num_threads=args.threads,
            login_url=args.login_url,
            login_data=args.login_data
        )
        
        report_text = engine.run_discovery()

        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"\n[OUTPUT] Comprehensive attack surface report saved to: {output_filename}")

    except KeyboardInterrupt:
        print("\n[INFO] Discovery interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

