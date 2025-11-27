#!/usr/bin/env python3
"""
Website Malware Scanner
Author: ITHPgm
GitHub: https://github.com/ITHPgm/
Description: A comprehensive website security scanner for detecting malicious code and vulnerabilities
"""

import requests
import re
import json
import urllib.parse
import ssl
import socket
from datetime import datetime
import argparse
import sys
import os
import hashlib
from bs4 import BeautifulSoup
import whois
import dns.resolver

class WebsiteScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {
            'url': target_url,
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'risk_level': 'Low',
            'summary': {}
        }
        
        # Malicious patterns to detect
        self.malicious_patterns = {
            'obfuscated_javascript': [
                r'eval\(.*\)',
                r'unescape\(.*\)',
                r'escape\(.*\)',
                r'fromCharCode\(.*\)',
                r'document\.write\(.*\)',
                r'setTimeout\(.*\)',
                r'setInterval\(.*\)',
                r'String\.fromCharCode\(.*\)',
                r'\\x[0-9a-fA-F]{2}',
                r'%[0-9a-fA-F]{2}'
            ],
            'suspicious_keywords': [
                r'base64_decode',
                r'gzinflate',
                r'str_rot13',
                r'create_function',
                r'assert\(.*\)',
                r'system\(.*\)',
                r'exec\(.*\)',
                r'shell_exec',
                r'passthru',
                r'popen',
                r'phpinfo',
                r'javascript:alert',
                r'onmouseover',
                r'onload=',
                r'onerror=',
                r'<iframe',
                r'<script>.*</script>'
            ],
            'malware_signatures': [
                r'c99shell',
                r'r57shell',
                r'phpspy',
                r'b374k',
                r'wso shell',
                r'c100 shell',
                r'madspot'
            ],
            'crypto_miners': [
                r'coinhive',
                r'cryptonight',
                r'miner\.js',
                r'webassembly\.instantiate',
                r'crypto\-miner',
                r'coin\-imp'
            ]
        }
        
        # Headers to mimic real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }

    def log_finding(self, category, severity, description, evidence=None):
        """Log security findings"""
        finding = {
            'category': category,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        self.results['findings'].append(finding)
        
        # Update risk level
        if severity == 'High' and self.results['risk_level'] != 'Critical':
            self.results['risk_level'] = 'High'
        elif severity == 'Critical':
            self.results['risk_level'] = 'Critical'
        elif severity == 'Medium' and self.results['risk_level'] == 'Low':
            self.results['risk_level'] = 'Medium'

    def check_ssl_certificate(self):
        """Check SSL certificate validity"""
        try:
            hostname = self.target_url.split('//')[1].split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expires - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.log_finding(
                            'SSL Security', 
                            'High', 
                            f'SSL certificate expires in {days_until_expiry} days',
                            f'Expiration date: {expires}'
                        )
                    else:
                        self.log_finding(
                            'SSL Security', 
                            'Info', 
                            f'SSL certificate valid for {days_until_expiry} more days'
                        )
                        
        except Exception as e:
            self.log_finding('SSL Security', 'Medium', f'SSL certificate check failed: {str(e)}')

    def fetch_website_content(self):
        """Fetch website content and external resources"""
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=15, verify=False)
            response.raise_for_status()
            
            self.results['status_code'] = response.status_code
            self.results['content_length'] = len(response.content)
            self.results['headers'] = dict(response.headers)
            
            return response.text, response.content
            
        except requests.RequestException as e:
            self.log_finding('Connection', 'High', f'Failed to fetch website: {str(e)}')
            return None, None

    def analyze_content(self, html_content, raw_content):
        """Analyze website content for malicious code"""
        if not html_content:
            return
            
        # Check for malicious patterns in HTML
        for category, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
                if matches:
                    self.log_finding(
                        'Malicious Code',
                        'High' if category in ['malware_signatures', 'crypto_miners'] else 'Medium',
                        f'Found {category.replace("_", " ")} pattern',
                        f'Pattern: {pattern}, Matches: {len(matches)}'
                    )
        
        # Analyze JavaScript files
        self.analyze_javascript_files(html_content)
        
        # Check for suspicious iframes
        self.check_suspicious_iframes(html_content)
        
        # Check for hidden content
        self.check_hidden_content(html_content)

    def analyze_javascript_files(self, html_content):
        """Analyze linked JavaScript files"""
        soup = BeautifulSoup(html_content, 'html.parser')
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags[:5]:  # Limit to first 5 external scripts
            script_src = script['src']
            if not script_src.startswith(('http', '//')):
                script_src = urllib.parse.urljoin(self.target_url, script_src)
                
            try:
                response = requests.get(script_src, headers=self.headers, timeout=10, verify=False)
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Check for obfuscated code
                    if len(js_content) > 10000 and 'eval' in js_content:
                        self.log_finding(
                            'JavaScript Analysis',
                            'High',
                            'Potential obfuscated JavaScript detected',
                            f'Script: {script_src}, Size: {len(js_content)} bytes'
                        )
                        
            except:
                pass  # Skip if we can't fetch the script

    def check_suspicious_iframes(self, html_content):
        """Check for suspicious iframe tags"""
        soup = BeautifulSoup(html_content, 'html.parser')
        iframes = soup.find_all('iframe')
        
        for iframe in iframes:
            src = iframe.get('src', '')
            style = iframe.get('style', '')
            
            # Check for hidden iframes
            if 'display:none' in style or 'visibility:hidden' in style:
                self.log_finding(
                    'Suspicious Elements',
                    'High',
                    'Hidden iframe detected',
                    f'Source: {src}, Style: {style}'
                )
            
            # Check for external iframes
            if src and not src.startswith('/') and self.target_url not in src:
                self.log_finding(
                    'External Content',
                    'Medium',
                    'External iframe detected',
                    f'Source: {src}'
                )

    def check_hidden_content(self, html_content):
        """Check for hidden or encoded content"""
        # Check for base64 encoded content
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, html_content)
        
        if len(base64_matches) > 10:
            self.log_finding(
                'Encoding',
                'Medium',
                'Multiple base64 encoded strings found',
                f'Found {len(base64_matches)} base64 strings'
            )
        
        # Check for hex encoded content
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        hex_matches = re.findall(hex_pattern, html_content)
        
        if len(hex_matches) > 5:
            self.log_finding(
                'Encoding',
                'High',
                'Hex encoded content found (possible obfuscation)',
                f'Found {len(hex_matches)} hex encoded sequences'
            )

    def generate_report(self):
        """Generate comprehensive scan report"""
        total_findings = len(self.results['findings'])
        high_risk = len([f for f in self.results['findings'] if f['severity'] in ['High', 'Critical']])
        medium_risk = len([f for f in self.results['findings'] if f['severity'] == 'Medium'])
        
        self.results['summary'] = {
            'total_findings': total_findings,
            'high_risk_findings': high_risk,
            'medium_risk_findings': medium_risk,
            'scan_duration': 'Completed'
        }
        
        return self.results

    def print_report(self):
        """Print formatted report to console"""
        print("\n" + "="*60)
        print(f"WEBSITE MALWARE SCAN REPORT")
        print("="*60)
        print(f"Target URL: {self.results['url']}")
        print(f"Scan Date: {self.results['timestamp']}")
        print(f"Risk Level: {self.results['risk_level']}")
        print(f"Total Findings: {len(self.results['findings'])}")
        
        print("\n" + "-"*60)
        print("DETAILED FINDINGS:")
        print("-"*60)
        
        for i, finding in enumerate(self.results['findings'], 1):
            print(f"\n{i}. [{finding['severity']}] {finding['category']}")
            print(f"   Description: {finding['description']}")
            if finding.get('evidence'):
                print(f"   Evidence: {finding['evidence']}")
        
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)

    def scan(self):
        """Perform complete website scan"""
        print(f"[+] Starting scan of {self.target_url}")
        
        # Step 1: SSL Certificate check
        print("[+] Checking SSL certificate...")
        self.check_ssl_certificate()
        
        # Step 2: Fetch website content
        print("[+] Fetching website content...")
        html_content, raw_content = self.fetch_website_content()
        
        if html_content:
            # Step 3: Analyze content
            print("[+] Analyzing website content...")
            self.analyze_content(html_content, raw_content)
        
        # Step 4: Generate report
        print("[+] Generating report...")
        self.generate_report()
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Website Malware Scanner')
    parser.add_argument('url', help='Target website URL to scan')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Input validation
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print("""
    ╔═══════════════════════════════════════════════╗
    ║           WEBSITE MALWARE SCANNER             ║
    ║           Author: ITHPgm                      ║
    ║           GitHub: github.com/ITHPgm           ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    try:
        # Initialize scanner
        scanner = WebsiteScanner(args.url)
        
        # Perform scan
        results = scanner.scan()
        
        # Print report
        scanner.print_report()
        
        # Save results if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Report saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
