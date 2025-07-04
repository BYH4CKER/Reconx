#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive Menu System for ReconX
Advanced reconnaissance tool with user-friendly interface
"""

import sys
import os
import json
from datetime import datetime
from colorama import init, Fore, Back, Style

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules import dns_scan, http_probe, ftp_scan, port_scan, vulnerability_scanner
from utils.banner import show_banner
from utils.formatter import print_success, print_error, print_info, print_warning, print_result
# Report generator will be defined in this file

# Initialize colorama
init(autoreset=True)

class ReconXInteractive:
    def __init__(self):
        self.target = ""
        self.timeout = 10
        self.results = {
            'target': '',
            'scan_time': datetime.now().isoformat(),
            'modules': {}
        }
        
    def show_main_menu(self):
        """Display main menu"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  RECONX - INTERACTIVE RECONNAISSANCE MENU")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}[1]{Style.RESET_ALL} Set Target (IP/Domain)")
        print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Port Scanning")
        print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} DNS Reconnaissance")  
        print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} HTTP Analysis")
        print(f"{Fore.YELLOW}[5]{Style.RESET_ALL} FTP Analysis")
        print(f"{Fore.RED}[6]{Style.RESET_ALL} Vulnerability Scanning")
        print(f"{Fore.YELLOW}[7]{Style.RESET_ALL} Full Reconnaissance")
        print(f"{Fore.YELLOW}[8]{Style.RESET_ALL} Generate Reports")
        print(f"{Fore.YELLOW}[9]{Style.RESET_ALL} Settings")
        print(f"{Fore.RED}[0]{Style.RESET_ALL} Exit")
        
        if self.target:
            print(f"\n{Fore.GREEN}Current Target: {self.target}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Timeout: {self.timeout}s{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}No target set! Please select option 1 first.{Style.RESET_ALL}")
    
    def set_target(self):
        """Set target IP or domain"""
        print(f"\n{Fore.CYAN}SET TARGET{Style.RESET_ALL}")
        print("-" * 20)
        
        target = input(f"{Fore.YELLOW}Enter target IP or domain: {Style.RESET_ALL}").strip()
        
        if target:
            self.target = target
            self.results['target'] = target
            print_success(f"Target set to: {target}")
        else:
            print_error("Invalid target!")
    
    def port_scan_menu(self):
        """Port scanning submenu"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print(f"\n{Fore.CYAN}PORT SCANNING MENU{Style.RESET_ALL}")
        print("-" * 30)
        
        print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} Fast Scan (Top 1000 ports)")
        print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Full Scan (All 65535 ports)")
        print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Stealth Scan (SYN)")
        print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} Service Detection")
        print(f"{Fore.YELLOW}[5]{Style.RESET_ALL} OS Detection")
        print(f"{Fore.YELLOW}[6]{Style.RESET_ALL} Aggressive Scan")
        print(f"{Fore.YELLOW}[7]{Style.RESET_ALL} Custom Port Range")
        print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Back to main menu")
        
        choice = input(f"\n{Fore.CYAN}Select scan type: {Style.RESET_ALL}").strip()
        
        scan_types = {
            '1': 'fast',
            '2': 'full', 
            '3': 'stealth',
            '4': 'service',
            '5': 'os',
            '6': 'aggressive'
        }
        
        if choice in scan_types:
            result = port_scan.scan_ports(self.target, scan_types[choice], self.timeout)
            self.results['modules']['port_scan'] = result
            
            # Show available services for further analysis
            if result.get('open_ports'):
                self.show_service_analysis_options(result['open_ports'])
                
        elif choice == '7':
            self.custom_port_scan()
        elif choice == '0':
            return
        else:
            print_error("Invalid choice!")
    
    def custom_port_scan(self):
        """Custom port range scanning"""
        print(f"\n{Fore.CYAN}CUSTOM PORT SCAN{Style.RESET_ALL}")
        print("-" * 25)
        
        ports_input = input(f"{Fore.YELLOW}Enter ports (e.g., 80,443,8080 or 1-1000): {Style.RESET_ALL}").strip()
        
        try:
            if '-' in ports_input:
                # Range format
                start, end = map(int, ports_input.split('-'))
                ports = list(range(start, end + 1))
            else:
                # Comma separated
                ports = [int(p.strip()) for p in ports_input.split(',')]
            
            result = port_scan.scan_specific_ports(self.target, ports, self.timeout)
            self.results['modules']['port_scan_custom'] = result
            
            if result.get('open_ports'):
                self.show_service_analysis_options(result['open_ports'])
                
        except ValueError:
            print_error("Invalid port format!")
    
    def show_service_analysis_options(self, open_ports):
        """Show options for analyzing detected services with security assessment"""
        print(f"\n{Fore.GREEN}DETECTED SERVICES:{Style.RESET_ALL}")
        
        available_modules = []
        high_risk_services = []
        critical_risk_services = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info.get('service', '').lower()
            version = port_info.get('version', '')
            risk = port_info.get('risk_level', 'unknown')
            
            # Color code by risk level
            if risk == 'critical':
                risk_color = f"{Fore.RED}"
                critical_risk_services.append(port_info)
            elif risk == 'high':
                risk_color = f"{Fore.YELLOW}"
                high_risk_services.append(port_info)
            elif risk == 'medium':
                risk_color = f"{Fore.CYAN}"
            else:
                risk_color = f"{Fore.GREEN}"
            
            print(f"    {risk_color}Port {port}: {service} {version} [{risk.upper()} RISK]{Style.RESET_ALL}")
            
            # Add security vulnerabilities info
            if port_info.get('vulnerabilities'):
                vulns = ', '.join(port_info['vulnerabilities'][:2])
                print(f"      {Fore.RED}⚠️  Vulnerabilities: {vulns}{Style.RESET_ALL}")
            
            # Check for specific service analysis modules
            if port in [21] or 'ftp' in service:
                if ('FTP Analysis', self.run_ftp_analysis) not in available_modules:
                    available_modules.append(('FTP Analysis', self.run_ftp_analysis))
            elif port in [80, 443, 8080, 8443] or 'http' in service or 'web' in service:
                if ('HTTP Analysis', self.run_http_analysis) not in available_modules:
                    available_modules.append(('HTTP Analysis', self.run_http_analysis))
            elif port in [22] or 'ssh' in service:
                available_modules.append(('SSH Analysis', self.run_ssh_analysis))
            elif port in [25, 587, 465] or 'smtp' in service:
                available_modules.append(('SMTP Analysis', self.run_smtp_analysis))
            elif port in [53] or 'dns' in service:
                available_modules.append(('DNS Analysis', self.run_dns_analysis))
            elif port in [445, 139] or 'smb' in service or 'netbios' in service:
                available_modules.append(('SMB Analysis', self.run_smb_analysis))
            elif port in [161] or 'snmp' in service:
                available_modules.append(('SNMP Analysis', self.run_snmp_analysis))
            elif port in [3389] or 'rdp' in service:
                available_modules.append(('RDP Analysis', self.run_rdp_analysis))
        
        # Show security warnings
        if critical_risk_services:
            print(f"\n{Fore.RED}🚨 CRITICAL SECURITY ALERT:{Style.RESET_ALL}")
            print(f"   {len(critical_risk_services)} critical risk services detected!")
            for service in critical_risk_services:
                recs = ', '.join(service.get('recommendations', [])[:2])
                print(f"   Port {service['port']}: {recs}")
        
        if high_risk_services:
            print(f"\n{Fore.YELLOW}⚠️  HIGH RISK SERVICES:{Style.RESET_ALL}")
            for service in high_risk_services:
                recs = ', '.join(service.get('recommendations', [])[:1])
                print(f"   Port {service['port']}: {recs}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_modules = []
        for item in available_modules:
            if item[0] not in seen:
                seen.add(item[0])
                unique_modules.append(item)
        
        if unique_modules:
            print(f"\n{Fore.CYAN}AVAILABLE SERVICE ANALYSIS:{Style.RESET_ALL}")
            for i, (name, _) in enumerate(unique_modules, 1):
                print(f"{Fore.YELLOW}[{i}]{Style.RESET_ALL} {name}")
            print(f"{Fore.YELLOW}[A]{Style.RESET_ALL} Run All Available Analysis")
            
            choice = input(f"\n{Fore.CYAN}Select analysis (or Enter to skip): {Style.RESET_ALL}").strip().upper()
            
            try:
                if choice == 'A':
                    print_info("Running all available service analysis...")
                    for name, func in unique_modules:
                        print(f"\n{Fore.CYAN}[{name}]{Style.RESET_ALL}")
                        print("-" * 30)
                        try:
                            func()
                        except Exception as e:
                            print_error(f"{name} failed: {str(e)}")
                elif choice and choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(unique_modules):
                        _, func = unique_modules[idx]
                        func()
            except (ValueError, IndexError):
                print_error("Invalid choice!")
    
    def run_dns_analysis(self):
        """Run DNS reconnaissance"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("Starting DNS reconnaissance...")
        result = dns_scan.scan_dns(self.target, timeout=self.timeout)
        self.results['modules']['dns'] = result
    
    def run_http_analysis(self):
        """Run HTTP analysis"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("Starting HTTP analysis...")
        result = http_probe.probe_http(self.target, timeout=self.timeout)
        self.results['modules']['http'] = result
    
    def run_ftp_analysis(self):
        """Run FTP analysis"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("Starting FTP analysis...")
        result = ftp_scan.scan_ftp(self.target, timeout=self.timeout)
        self.results['modules']['ftp'] = result
    
    def run_ssh_analysis(self):
        """Run SSH analysis (placeholder)"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("SSH analysis not yet implemented - showing basic port scan results")
        print_warning("Recommendation: Use key-based authentication, disable root login")
    
    def run_smtp_analysis(self):
        """Run SMTP analysis (placeholder)"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("SMTP analysis not yet implemented - showing basic port scan results")
        print_warning("Recommendation: Configure authentication, disable open relay")
    
    def run_smb_analysis(self):
        """Run SMB analysis (placeholder)"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("SMB analysis not yet implemented - showing basic port scan results")
        print_error("CRITICAL: SMB can be vulnerable to EternalBlue and other exploits")
        print_warning("Recommendation: Apply latest patches, disable SMBv1")
    
    def run_snmp_analysis(self):
        """Run SNMP analysis (placeholder)"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("SNMP analysis not yet implemented - showing basic port scan results")
        print_warning("Recommendation: Change default community strings, use SNMPv3")
    
    def run_rdp_analysis(self):
        """Run RDP analysis (placeholder)"""
        if not self.target:
            print_error("Please set a target first!")
            return
            
        print_info("RDP analysis not yet implemented - showing basic port scan results")
        print_error("HIGH RISK: RDP can be vulnerable to brute force and BlueKeep")
        print_warning("Recommendation: Enable NLA, use strong passwords, consider VPN")
    
    def run_vulnerability_scan(self):
        """Run comprehensive vulnerability scanning"""
        if not self.target:
            print_error("Please set a target first!")
            return
        
        print(f"\n{Fore.RED}{'='*60}")
        print(f"  VULNERABILITY SCANNING")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        # First, check if we have port scan results
        port_scan_results = self.results.get('modules', {}).get('port_scan')
        
        if not port_scan_results or not port_scan_results.get('open_ports'):
            print_warning("No port scan results found. Running port scan first...")
            
            # Run port scan first
            port_result = port_scan.scan_ports(self.target, "service", self.timeout)
            self.results['modules']['port_scan'] = port_result
            
            if not port_result.get('open_ports'):
                print_error("No open ports found. Cannot proceed with vulnerability scanning.")
                return
            
            open_ports = port_result['open_ports']
        else:
            open_ports = port_scan_results['open_ports']
            print_success(f"Using existing port scan results: {len(open_ports)} open ports")
        
        # Run vulnerability scan
        print_info("Starting comprehensive vulnerability scanning...")
        
        try:
            vuln_results = vulnerability_scanner.scan_vulnerabilities(
                self.target, 
                open_ports, 
                self.timeout * 2  # Double timeout for vulnerability scanning
            )
            
            self.results['modules']['vulnerability_scan'] = vuln_results
            
            # Show detailed results
            self.display_vulnerability_details(vuln_results)
            
            # Ask for HTML report
            if vuln_results.get('total_vulnerabilities', 0) > 0:
                create_report = input(f"\n{Fore.CYAN}Create detailed HTML vulnerability report? (y/N): {Style.RESET_ALL}").strip().lower()
                
                if create_report in ['y', 'yes']:
                    self.generate_vulnerability_report(vuln_results)
            
        except Exception as e:
            print_error(f"Vulnerability scan failed: {str(e)}")
    
    def display_vulnerability_details(self, vuln_results):
        """Display detailed vulnerability information"""
        vulnerabilities = vuln_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print_info("No vulnerabilities detected.")
            return
        
        print(f"\n{Fore.YELLOW}DETAILED VULNERABILITY ANALYSIS:{Style.RESET_ALL}")
        
        # Group by severity
        by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            by_severity[severity].append(vuln)
        
        # Display by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            vulns = by_severity[severity]
            if not vulns:
                continue
            
            severity_colors = {
                'critical': Fore.RED,
                'high': Fore.YELLOW,
                'medium': Fore.CYAN,
                'low': Fore.GREEN
            }
            
            color = severity_colors[severity]
            
            print(f"\n{color}[{severity.upper()}] SEVERITY ({len(vulns)} vulnerabilities):{Style.RESET_ALL}")
            
            for i, vuln in enumerate(vulns[:5], 1):  # Show first 5 of each severity
                if vuln['type'] == 'cve':
                    exploit_count = len(vuln.get('exploits', []))
                    exploit_text = f" [{exploit_count} exploits]" if exploit_count > 0 else ""
                    
                    print(f"  {color}{i}. {vuln.get('cve_id', 'N/A')}: {vuln.get('title', 'Unknown')}{exploit_text}{Style.RESET_ALL}")
                    print(f"     Port: {vuln.get('port', 'N/A')} | Service: {vuln.get('service', 'N/A')} | CVSS: {vuln.get('cvss', 'N/A')}")
                    
                    # Show exploits
                    for exploit in vuln.get('exploits', [])[:2]:
                        print(f"     {Fore.GREEN}|- Exploit: {exploit.get('title', 'Unknown')} ({exploit.get('type', 'unknown')}){Style.RESET_ALL}")
                else:
                    print(f"  {color}{i}. {vuln.get('title', 'Unknown')}{Style.RESET_ALL}")
                    print(f"     Port: {vuln.get('port', 'N/A')} | Script: {vuln.get('script', 'N/A')}")
                
                print()
    
    def generate_vulnerability_report(self, vuln_results):
        """Generate HTML vulnerability report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = self.target.replace('.', '_').replace(':', '_')
            filename = f"vulnerability_report_{target_clean}_{timestamp}.html"
            
            # Enhanced HTML report with vulnerability details
            enhanced_results = self.results.copy()
            enhanced_results['vulnerability_details'] = vuln_results
            
            generate_html_report(enhanced_results, filename)
            
            print_success(f"Detailed vulnerability report generated: {filename}")
            print_info(f"Open the report in your browser to view detailed vulnerability information.")
            
        except Exception as e:
            print_error(f"Failed to generate vulnerability report: {str(e)}")
    
    def run_full_reconnaissance(self):
        """Run all reconnaissance modules including vulnerability scanning"""
        if not self.target:
            print_error("Please set a target first!")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  FULL RECONNAISSANCE & VULNERABILITY SCAN")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print_info(f"Starting comprehensive security analysis of {self.target}")
        
        # 1. Port Scanning
        print_info("Step 1/5: Port Scanning...")
        try:
            port_result = port_scan.scan_ports(self.target, "service", self.timeout)
            self.results['modules']['port_scan'] = port_result
            
            if port_result.get('open_ports'):
                print_success(f"Found {len(port_result['open_ports'])} open ports")
            else:
                print_warning("No open ports found")
        except Exception as e:
            print_error(f"Port scanning failed: {str(e)}")
            return
        
        # 2. DNS Reconnaissance
        print_info("Step 2/5: DNS Reconnaissance...")
        try:
            dns_result = dns_scan.scan_dns(self.target, self.timeout)
            self.results['modules']['dns_scan'] = dns_result
            
            if dns_result.get('subdomains'):
                print_success(f"Found {len(dns_result['subdomains'])} subdomains")
        except Exception as e:
            print_error(f"DNS reconnaissance failed: {str(e)}")
        
        # 3. HTTP Analysis (for web servers)
        web_ports = [80, 443, 8080, 8443]
        open_web_ports = [port for port in port_result.get('open_ports', []) if port.get('port') in web_ports]
        
        if open_web_ports:
            print_info("Step 3/5: HTTP Analysis...")
            try:
                http_result = http_probe.probe_http(self.target, self.timeout, [port['port'] for port in open_web_ports])
                self.results['modules']['http_probe'] = http_result
                
                if http_result.get('services'):
                    print_success(f"Analyzed {len(http_result['services'])} HTTP services")
            except Exception as e:
                print_error(f"HTTP analysis failed: {str(e)}")
        else:
            print_warning("Step 3/5: No web servers found, skipping HTTP analysis")
        
        # 4. FTP Analysis (if FTP port is open)
        ftp_ports = [21]
        open_ftp_ports = [port for port in port_result.get('open_ports', []) if port.get('port') in ftp_ports]
        
        if open_ftp_ports:
            print_info("Step 4/5: FTP Analysis...")
            try:
                ftp_result = ftp_scan.scan_ftp(self.target, self.timeout, [port['port'] for port in open_ftp_ports])
                self.results['modules']['ftp_scan'] = ftp_result
                
                if ftp_result.get('services'):
                    print_success(f"Analyzed {len(ftp_result['services'])} FTP services")
            except Exception as e:
                print_error(f"FTP analysis failed: {str(e)}")
        else:
            print_warning("Step 4/5: No FTP servers found, skipping FTP analysis")
        
        # 5. VULNERABILITY SCANNING (NEW!)
        if port_result.get('open_ports'):
            print_info("Step 5/5: Comprehensive Vulnerability Scanning...")
            
            try:
                vuln_results = vulnerability_scanner.scan_vulnerabilities(
                    self.target, 
                    port_result['open_ports'], 
                    self.timeout * 2  # Double timeout for vulnerability scanning
                )
                
                self.results['modules']['vulnerability_scan'] = vuln_results
                self.results['vulnerability_details'] = vuln_results  # For enhanced HTML report
                
                total_vulns = vuln_results.get('total_vulnerabilities', 0)
                critical_count = vuln_results.get('critical_count', 0)
                high_count = vuln_results.get('high_count', 0)
                
                if total_vulns > 0:
                    print_success(f"Vulnerability scan completed: {total_vulns} vulnerabilities found!")
                    if critical_count > 0 or high_count > 0:
                        print_error(f"[CRITICAL ALERT] {critical_count + high_count} critical/high severity vulnerabilities detected!")
                else:
                    print_success("No major vulnerabilities detected")
                
            except Exception as e:
                print_error(f"Vulnerability scan failed: {str(e)}")
        else:
            print_warning("Step 5/5: No open ports found, skipping vulnerability scan")
        
        print_success("Full reconnaissance & vulnerability analysis completed!")
        
        # Generate automatic comprehensive reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = self.target.replace('.', '_').replace(':', '_')
        
        # JSON Report
        json_filename = f"full_security_analysis_{target_clean}_{timestamp}.json"
        generate_json_report(self.results, json_filename)
        
        # Enhanced HTML Report with Vulnerability Details
        html_filename = f"full_security_analysis_{target_clean}_{timestamp}.html"
        generate_html_report(self.results, html_filename)
        
        print_success(f"Security analysis reports generated:")
        print_info(f"   JSON: {json_filename}")
        print_info(f"   HTML: {html_filename}")
        
        # Show summary of findings
        self.display_reconnaissance_summary()
    
    def display_reconnaissance_summary(self):
        """Display a summary of reconnaissance findings"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  RECONNAISSANCE SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        # Port scan summary
        port_scan_result = self.results.get('modules', {}).get('port_scan', {})
        open_ports = port_scan_result.get('open_ports', [])
        print_result("Open Ports", len(open_ports))
        
        # DNS summary
        dns_result = self.results.get('modules', {}).get('dns_scan', {})
        subdomains = dns_result.get('subdomains', [])
        print_result("Subdomains Found", len(subdomains))
        
        # HTTP summary
        http_result = self.results.get('modules', {}).get('http_probe', {})
        http_services = http_result.get('services', [])
        print_result("HTTP Services", len(http_services))
        
        # FTP summary
        ftp_result = self.results.get('modules', {}).get('ftp_scan', {})
        ftp_services = ftp_result.get('services', [])
        print_result("FTP Services", len(ftp_services))
        
        # Vulnerability summary
        vuln_result = self.results.get('modules', {}).get('vulnerability_scan', {})
        if vuln_result:
            total_vulns = vuln_result.get('total_vulnerabilities', 0)
            critical_count = vuln_result.get('critical_count', 0)
            high_count = vuln_result.get('high_count', 0)
            
            print_result("Total Vulnerabilities", total_vulns)
            if critical_count > 0:
                print(f"    {Fore.RED}[CRITICAL] {critical_count}{Style.RESET_ALL}")
            if high_count > 0:
                print(f"    {Fore.YELLOW}[HIGH] {high_count}{Style.RESET_ALL}")
            
            # Show exploit count
            exploit_matches = vuln_result.get('exploit_matches', {})
            if exploit_matches:
                total_exploits = sum(len(exploits) for exploits in exploit_matches.values())
                print_result("Available Exploits", total_exploits)
        
        print()
    
    def generate_reports_menu(self):
        """Generate reports menu"""
        if not self.results.get('modules'):
            print_error("No scan results available! Run some reconnaissance first.")
            return
            
        print(f"\n{Fore.CYAN}GENERATE REPORTS{Style.RESET_ALL}")
        print("-" * 25)
        
        print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} JSON Report")
        print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} HTML Report")
        print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Both Reports")
        print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Back to main menu")
        
        choice = input(f"\n{Fore.CYAN}Select report type: {Style.RESET_ALL}").strip()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = self.target.replace('.', '_').replace(':', '_')
        
        if choice in ['1', '3']:
            filename = f"reconx_report_{target_clean}_{timestamp}.json"
            generate_json_report(self.results, filename)
            
        if choice in ['2', '3']:
            filename = f"reconx_report_{target_clean}_{timestamp}.html"
            generate_html_report(self.results, filename)
    
    def settings_menu(self):
        """Settings configuration menu"""
        print(f"\n{Fore.CYAN}SETTINGS{Style.RESET_ALL}")
        print("-" * 15)
        
        print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} Set Timeout (Current: {self.timeout}s)")
        print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Check NMAP Installation")
        print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Back to main menu")
        
        choice = input(f"\n{Fore.CYAN}Select option: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            try:
                new_timeout = int(input(f"{Fore.YELLOW}Enter timeout in seconds: {Style.RESET_ALL}"))
                if new_timeout > 0:
                    self.timeout = new_timeout
                    print_success(f"Timeout set to {new_timeout} seconds")
                else:
                    print_error("Timeout must be positive!")
            except ValueError:
                print_error("Invalid timeout value!")
                
        elif choice == '2':
            if port_scan.check_nmap_available():
                print_success("NMAP is available and ready to use")
            else:
                print_error("NMAP is not installed or not in PATH")
                print_info("Install with: sudo apt install nmap")
    
    def run(self):
        """Main interactive loop"""
        show_banner()
        
        while True:
            try:
                self.show_main_menu()
                choice = input(f"\n{Fore.CYAN}Select option: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    self.set_target()
                elif choice == '2':
                    self.port_scan_menu()
                elif choice == '3':
                    self.run_dns_analysis()
                elif choice == '4':
                    self.run_http_analysis()
                elif choice == '5':
                    self.run_ftp_analysis()
                elif choice == '6':
                    self.run_vulnerability_scan()
                elif choice == '7':
                    self.run_full_reconnaissance()
                elif choice == '8':
                    self.generate_reports_menu()
                elif choice == '9':
                    self.settings_menu()
                elif choice == '0':
                    print_success("Thank you for using ReconX!")
                    break
                else:
                    print_error("Invalid choice! Please select a valid option.")
                    
            except KeyboardInterrupt:
                print_warning("\nOperation interrupted by user!")
                break
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")

def generate_json_report(results, filename="reconx_report.json"):
    """Generate JSON report"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print_success(f"JSON report generated: {filename}")
        return True
        
    except Exception as e:
        print_error(f"Failed to generate JSON report: {str(e)}")
        return False

def generate_html_report(results, filename="reconx_report.html"):
    """Generate HTML report"""
    try:
        html_content = build_html_report(results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print_success(f"HTML report generated: {filename}")
        return True
        
    except Exception as e:
        print_error(f"Failed to generate HTML report: {str(e)}")
        return False

def build_html_report(results):
    """Build HTML report content"""
    target = results.get('target', 'Unknown')
    scan_time = results.get('scan_time', datetime.now().isoformat())
    modules = results.get('modules', {})
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Report - {target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 5px solid #007bff;
        }}
        
        .module {{
            margin-bottom: 40px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .module-header {{
            background: #343a40;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .module-content {{
            padding: 20px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        table th {{
            background: #495057;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        table tr:nth-child(even) {{
            background: #f8f9fa;
        }}
        
        .vulnerability {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
            background: #28a745;
        }}
        
        .footer {{
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ReconX Security Report</h1>
        </div>
        
        <div class="content">
            <div class="summary">
                <h2>📋 Scan Summary</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Date:</strong> {scan_time}</p>
                <p><strong>Modules Executed:</strong> {len(modules)}</p>
            </div>
    """
    
    # Add module results
    for module_name, module_data in modules.items():
        if module_data:
            html += f"""
            <div class="module">
                <div class="module-header">
                    {module_name.replace('_', ' ').title()}
                </div>
                <div class="module-content">
                    <pre>{json.dumps(module_data, indent=2)}</pre>
                </div>
            </div>
            """
    
    html += """
        </div>
        
        <div class="footer">
            Generated by ReconX v1.0 - Advanced Network Security Discovery Tool
        </div>
    </div>
</body>
</html>
    """
    
    return html

def main():
    """Main function"""
    reconx = ReconXInteractive()
    reconx.run()

if __name__ == "__main__":
    main() 