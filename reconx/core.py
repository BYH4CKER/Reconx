#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconX - Extended Reconnaissance Tool
Modüler siber güvenlik keşif ve zafiyet analiz aracı
"""

import argparse
import json
import sys
import time
import ipaddress
from datetime import datetime
from colorama import init, Fore, Back, Style

# Modülleri import et
from modules import dns_scan, http_probe, ftp_scan
from utils.banner import show_banner
from utils.formatter import print_success, print_error, print_info, print_warning

# Colorama'yı başlat
init(autoreset=True)

class ReconX:
    def __init__(self, target, timeout=5, json_output=None):
        self.target = target
        self.timeout = timeout
        self.json_output = json_output
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'modules': {}
        }
        
    def validate_target(self):
        """Validate target IP or domain"""
        try:
            # Check if it's an IP address
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            # Basic domain format check
            if '.' in self.target and len(self.target) > 3:
                return True
            return False
    
    def run_dns_scan(self):
        """Execute DNS scanning module"""
        print_info("Starting DNS reconnaissance...")
        try:
            result = dns_scan.scan_dns(self.target, timeout=self.timeout)
            self.results['modules']['dns'] = result
            return result
        except Exception as e:
            print_error(f"DNS scan error: {str(e)}")
            return None
    
    def run_http_probe(self):
        """Execute HTTP probe module"""
        print_info("Starting HTTP analysis...")
        try:
            result = http_probe.probe_http(self.target, timeout=self.timeout)
            self.results['modules']['http'] = result
            return result
        except Exception as e:
            print_error(f"HTTP probe error: {str(e)}")
            return None
    
    def run_ftp_scan(self):
        """Execute FTP scanning module"""
        print_info("Starting FTP reconnaissance...")
        try:
            result = ftp_scan.scan_ftp(self.target, timeout=self.timeout)
            self.results['modules']['ftp'] = result
            return result
        except Exception as e:
            print_error(f"FTP scan error: {str(e)}")
            return None
    
    def save_json_results(self):
        """Save results in JSON format"""
        if self.json_output:
            try:
                with open(self.json_output, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
                print_success(f"Results saved to JSON: {self.json_output}")
            except Exception as e:
                print_error(f"JSON save error: {str(e)}")
    
    def run_all_scans(self):
        """Execute all scanning modules sequentially"""
        if not self.validate_target():
            print_error("Invalid target! Please provide a valid IP address or domain name.")
            return False
        
        print_info(f"Target: {self.target}")
        print_info(f"Timeout: {self.timeout} seconds")
        print("=" * 60)
        
        # Execute modules sequentially
        modules = [
            ("DNS Reconnaissance", self.run_dns_scan),
            ("HTTP Analysis", self.run_http_probe),
            ("FTP Reconnaissance", self.run_ftp_scan)
        ]
        
        for module_name, module_func in modules:
            print(f"\n{Fore.CYAN}[{module_name}]{Style.RESET_ALL}")
            print("-" * 30)
            start_time = time.time()
            
            result = module_func()
            
            end_time = time.time()
            elapsed = end_time - start_time
            
            if result:
                print_success(f"{module_name} completed ({elapsed:.2f}s)")
            else:
                print_warning(f"{module_name} failed ({elapsed:.2f}s)")
        
        # Save JSON output if specified
        self.save_json_results()
        
        print("\n" + "=" * 60)
        print_success("All reconnaissance modules completed!")
        
        return True

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='ReconX - Extended Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 reconx.py --target 192.168.1.10
  python3 reconx.py --target example.com --timeout 10
  python3 reconx.py --target test.com --json results.json
        """
    )
    
    parser.add_argument('--target', '-t', required=True,
                       help='Target IP address or domain name')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Connection timeout in seconds [default: 5]')
    parser.add_argument('--json', '-j', dest='json_output',
                       help='Save results in JSON format')
    
    args = parser.parse_args()
    
    # ReconX nesnesini oluştur ve çalıştır
    reconx = ReconX(
        target=args.target,
        timeout=args.timeout,
        json_output=args.json_output
    )
    
    try:
        success = reconx.run_all_scans()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user!")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 