import argparse
import sys
from urllib.parse import urlparse

from core.engine import DiscoveryEngine

def main():
    parser = argparse.ArgumentParser(
        description="A hybrid, multi-threaded attack surface discovery engine.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example:
  # Basic unauthenticated scan
  python mapper.py http://testphp.vulnweb.com/

  # Scan with authentication
  python mapper.py http://example.com/dashboard --login-url http://example.com/login --login-data "user=admin&pass=secret"
"""
    )
    parser.add_argument("url", help="The base URL to start discovery from.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads to use. Default is 10.")
    
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument("--login-url", help="The URL where the login form is submitted.")
    auth_group.add_argument("--login-data", help="POST data for login (e.g., 'user=admin&pass=123').")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    base_url = args.url if urlparse(args.url).scheme else "http://" + args.url

    try:
        engine = DiscoveryEngine(
            base_url, 
            max_depth=2,  # Depth is hardcoded to 2
            num_threads=args.threads,
            login_url=args.login_url, 
            login_data=args.login_data
        )
        engine.run_discovery()
    except KeyboardInterrupt:
        print("\n[INFO] Discovery interrupted by user. Exiting.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()