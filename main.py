import argparse
from scanner.core import WebSecurityScanner

def main():
    parser = argparse.ArgumentParser(description="Python Web Vulnerability Scanner")
    parser.add_argument("url", help="Target base URL (including http(s)://)")
    parser.add_argument("--depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("--workers", type=int, default=5, help="Number of concurrent workers (default: 5)")
    parser.add_argument("--login-url", help="Optional login URL for authentication")
    parser.add_argument("--username", help="Optional username for login")
    parser.add_argument("--password", help="Optional password for login")

    args = parser.parse_args()

    scanner = WebSecurityScanner(
        base_url=args.url,
        max_depth=args.depth,
        max_workers=args.workers,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
    )

    print(f"Starting crawl and scan of {args.url}...\n")
    scanner.crawl(args.url)
    scanner.scan()
    scanner.generate_report()

if __name__ == "__main__":
    main()
