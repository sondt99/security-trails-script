import argparse
import sys
import requests
import json
from pathlib import Path
from typing import List, Dict, Optional


class SubdomainScanner:
    """Subdomain scanner using SecurityTrails API"""

    def __init__(self, key_file: str = "list-api_key.txt"):
        self.key_file = key_file
        self.api_keys = self._read_api_keys()
        self.valid_key = None

    def _read_api_keys(self) -> List[str]:
        """Read API keys from file"""
        key_path = Path(self.key_file)
        if not key_path.exists():
            print(f"[!] Error: {self.key_file} not found!")
            sys.exit(1)

        with open(self.key_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def _get_valid_key(self, domain: str) -> Optional[str]:
        """Find a working API key for the domain"""
        print(f"[*] Testing {len(self.api_keys)} API keys...")
        for i, key in enumerate(self.api_keys, 1):
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {
                'accept': 'application/json',
                'APIKEY': key
            }
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    print(f"[+] Valid key found (#{i}): {key[:12]}...")
                    return key
            except requests.RequestException:
                continue
        return None

    def scan(self, domain: str) -> Dict:
        """Scan subdomains for the given domain"""
        print(f"[*] Scanning subdomains for: {domain}")
        print("=" * 50)

        # Get valid API key
        self.valid_key = self._get_valid_key(domain)
        if not self.valid_key:
            return {"error": "No valid API key found"}

        # Query SecurityTrails API
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            'accept': 'application/json',
            'APIKEY': self.valid_key
        }

        try:
            response = requests.get(url, headers=headers, timeout=30)
            data = response.json()

            # Check for API errors
            if 'message' in data and 'code' in data:
                return {"error": f"API Error: {data['message']}"}

            # Build subdomain list
            subdomains = [domain]  # Include root domain
            for sub in data.get('subdomains', []):
                subdomains.append(f"{sub}.{domain}")

            return {
                'domain': domain,
                'total': data.get('subdomain_count', 0),
                'subdomains': sorted(set(subdomains))
            }

        except requests.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}

    def save_results(self, results: Dict, output_file: str):
        """Save scan results to file"""
        with open(output_file, 'w') as f:
            if 'error' in results:
                f.write(f"Error: {results['error']}\n")
            else:
                for subdomain in results['subdomains']:
                    f.write(f"{subdomain}\n")
        print(f"[+] Results saved to: {output_file}")

    def create_key_file(self, output_file: str = "key.txt"):
        """Create a key.txt file with current valid key"""
        if self.valid_key:
            with open(output_file, 'w') as f:
                f.write(self.valid_key)
            print(f"[+] API key saved to: {output_file}")
        else:
            print("[!] No valid key available to save")

def main():
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description="Subdomain Scanner - Scan subdomains using SecurityTrails API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_scanner.py -d example.com
  python subdomain_scanner.py -d example.com -o results.txt
  python subdomain_scanner.py -d example.com --save-key
  python subdomain_scanner.py -d example.com -o results.txt --save-key
        """
    )

    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Target domain to scan (e.g., example.com)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file to save results'
    )
    parser.add_argument(
        '-k', '--key-file',
        default='list-api_key.txt',
        help='API key file path (default: list-api_key.txt)'
    )
    parser.add_argument(
        '--save-key',
        action='store_true',
        help='Save valid API key to key.txt'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )

    args = parser.parse_args()

    # Validate domain format
    domain = args.domain.strip().lower()
    if '.' not in domain:
        print(f"[!] Invalid domain: {domain}")
        sys.exit(1)

    # Initialize scanner
    scanner = SubdomainScanner(key_file=args.key_file)

    # Perform scan
    results = scanner.scan(domain)

    # Display results
    if 'error' in results:
        print(f"[!] {results['error']}")
        sys.exit(1)

    print(f"\n[+] Target Domain: {results['domain']}")
    print(f"[+] Total Subdomains: {results['total']}")
    print("=" * 50)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n[+] Subdomains found:")
        for i, subdomain in enumerate(results['subdomains'], 1):
            print(f"    {i:3d}. {subdomain}")

    print("\n" + "=" * 50)
    print(f"[+] Scan completed! Found {len(results['subdomains'])} subdomains")

    # Save results if output file specified
    if args.output:
        scanner.save_results(results, args.output)

    # Save key if requested
    if args.save_key:
        scanner.create_key_file()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
