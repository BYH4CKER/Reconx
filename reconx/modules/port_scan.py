#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanning Module with Security Risk Analysis
Network port discovery using NMAP with vulnerability assessment
"""

import subprocess
import json
import re
import sys
import os
from colorama import Fore, Style
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.formatter import print_success, print_error, print_info, print_result, print_warning

def scan_ports(target, scan_type="fast", timeout=10):
    """
    Port scanning function using NMAP with security analysis
    """
    results = {
        'target': target,
        'scan_type': scan_type,
        'open_ports': [],
        'services': {},
        'os_info': '',
        'status': 'success'
    }
    
    if not check_nmap_available():
        print_error("NMAP is not installed or not in PATH")
        results['status'] = 'failed'
        return results
    
    nmap_cmd = build_nmap_command(target, scan_type, timeout)
    
    try:
        print_info(f"Starting {scan_type} port scan on {target}...")
        print_info(f"Command: {' '.join(nmap_cmd)}")
        
        process = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=timeout * 10
        )
        
        if process.returncode == 0:
            results = parse_nmap_output(process.stdout, results)
            
            if results['open_ports']:
                print_success(f"Port scan completed: {len(results['open_ports'])} open ports found")
                
                high_risk_ports = []
                critical_risk_ports = []
                
                for port_info in results['open_ports']:
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    risk = port_info.get('risk_level', 'unknown')
                    
                    if risk == 'critical':
                        color = f"{Fore.RED}"
                        critical_risk_ports.append(port_info)
                    elif risk == 'high':
                        color = f"{Fore.YELLOW}"
                        high_risk_ports.append(port_info)
                    elif risk == 'medium':
                        color = f"{Fore.CYAN}"
                    else:
                        color = f"{Fore.GREEN}"
                    
                    print(f"    {color}Port {port_info['port']}/{port_info['protocol']}: {port_info['state']} - {service} {version} [{risk.upper()} RISK]{Style.RESET_ALL}")
                
                if critical_risk_ports:
                    print_error(f"\n🚨 CRITICAL RISK SERVICES DETECTED: {len(critical_risk_ports)}")
                    for port_info in critical_risk_ports:
                        vulns = ', '.join(port_info.get('vulnerabilities', []))
                        print_error(f"   Port {port_info['port']}: {vulns}")
                
                if high_risk_ports:
                    print_warning(f"\n⚠️  HIGH RISK SERVICES DETECTED: {len(high_risk_ports)}")
                    for port_info in high_risk_ports:
                        vulns = ', '.join(port_info.get('vulnerabilities', [])[:2])
                        print_warning(f"   Port {port_info['port']}: {vulns}")
                        
            else:
                print_info("No open ports detected")
        else:
            print_error(f"NMAP scan failed: {process.stderr}")
            results['status'] = 'failed'
            
    except subprocess.TimeoutExpired:
        print_error(f"Port scan timed out after {timeout * 10} seconds")
        results['status'] = 'timeout'
    except Exception as e:
        print_error(f"Port scan error: {str(e)}")
        results['status'] = 'failed'
    
    return results

def check_nmap_available():
    """Check if NMAP is available in system PATH"""
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def build_nmap_command(target, scan_type, timeout):
    """Build NMAP command based on scan type"""
    base_cmd = ['nmap']
    
    scan_configs = {
        "fast": ['-F', '-T4'],
        "full": ['-p-', '-T4'],
        "stealth": ['-sS', '-T3'],
        "service": ['-sV', '-T4'],
        "os": ['-O', '-T4'],
        "aggressive": ['-A', '-T4']
    }
    
    cmd = base_cmd + scan_configs.get(scan_type, ['-F', '-T4']) + [target]
    cmd.extend(['--host-timeout', f'{timeout}s'])
    
    return cmd

def parse_nmap_output(nmap_output, results):
    """Parse NMAP output and extract port information with security analysis"""
    lines = nmap_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        port_pattern = r'(\d+)/(\w+)\s+(\w+)\s+(.+)'
        port_match = re.match(port_pattern, line)
        
        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_info = port_match.group(4)
            
            if state == 'open':
                service_parts = service_info.split()
                service_name = service_parts[0] if service_parts else 'unknown'
                version_info = ' '.join(service_parts[1:]) if len(service_parts) > 1 else ''
                
                security_info = get_port_security_info(port)
                
                port_info = {
                    'port': port,
                    'protocol': protocol,
                    'state': state,
                    'service': service_name,
                    'version': version_info,
                    'risk_level': security_info.get('risk', 'unknown'),
                    'vulnerabilities': security_info.get('vulnerabilities', []),
                    'recommendations': security_info.get('recommendations', [])
                }
                
                results['open_ports'].append(port_info)
                results['services'][f"{port}/{protocol}"] = {
                    'service': service_name,
                    'version': version_info,
                    'risk_level': security_info.get('risk', 'unknown')
                }
        
        if 'OS:' in line or 'Running:' in line:
            results['os_info'] = line
    
    return results

def scan_specific_ports(target, ports, timeout=10):
    """Scan specific ports"""
    if not check_nmap_available():
        print_error("NMAP is not installed")
        return {'status': 'failed', 'open_ports': []}
    
    port_list = ','.join(map(str, ports))
    nmap_cmd = ['nmap', '-p', port_list, '-sV', '-T4', '--host-timeout', f'{timeout}s', target]
    
    try:
        print_info(f"Scanning specific ports: {port_list}")
        
        process = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=timeout * 2)
        
        results = {
            'target': target,
            'scan_type': 'specific_ports',
            'open_ports': [],
            'services': {},
            'status': 'success'
        }
        
        if process.returncode == 0:
            results = parse_nmap_output(process.stdout, results)
            return results
        else:
            print_error(f"Port scan failed: {process.stderr}")
            results['status'] = 'failed'
            return results
            
    except Exception as e:
        print_error(f"Specific port scan error: {str(e)}")
        return {'status': 'failed', 'open_ports': []}

def get_common_ports():
    """Return dictionary of common ports and their services"""
    return {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
        110: 'POP3', 135: 'MS RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
        587: 'SMTP (Submission)', 631: 'IPP', 636: 'LDAPS', 993: 'IMAPS',
        995: 'POP3S', 1433: 'Microsoft SQL Server', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM (HTTP)', 8000: 'HTTP-alt',
        8080: 'HTTP Proxy', 8443: 'HTTPS-alt', 9200: 'Elasticsearch'
    }

def get_port_security_info(port):
    """Get security information for specific port"""
    security_db = {
        21: {'risk': 'high', 'vulnerabilities': ['Anonymous FTP', 'FTP Bounce Attack'], 'recommendations': ['Disable anonymous', 'Use SFTP']},
        22: {'risk': 'medium', 'vulnerabilities': ['SSH Brute Force', 'Weak Keys'], 'recommendations': ['Key-based auth', 'Disable root login']},
        23: {'risk': 'critical', 'vulnerabilities': ['Plain text transmission', 'No encryption'], 'recommendations': ['Replace with SSH', 'Disable service']},
        25: {'risk': 'medium', 'vulnerabilities': ['Open Relay', 'SMTP enumeration'], 'recommendations': ['Configure auth', 'Anti-spam measures']},
        53: {'risk': 'medium', 'vulnerabilities': ['DNS Amplification', 'Zone Transfer'], 'recommendations': ['Disable recursion', 'Rate limiting']},
        80: {'risk': 'medium', 'vulnerabilities': ['Web app vulns', 'Directory traversal'], 'recommendations': ['Use HTTPS', 'Security headers']},
        135: {'risk': 'high', 'vulnerabilities': ['RPC exploits', 'Remote code execution'], 'recommendations': ['Firewall restrictions', 'Patch system']},
        139: {'risk': 'high', 'vulnerabilities': ['NetBIOS enumeration', 'Null sessions'], 'recommendations': ['Disable NetBIOS', 'SMB hardening']},
        143: {'risk': 'medium', 'vulnerabilities': ['IMAP injection', 'Brute force'], 'recommendations': ['Use IMAPS', 'Strong passwords']},
        161: {'risk': 'medium', 'vulnerabilities': ['Default community strings', 'Information disclosure'], 'recommendations': ['Change defaults', 'SNMPv3']},
        389: {'risk': 'medium', 'vulnerabilities': ['LDAP injection', 'Anonymous bind'], 'recommendations': ['Disable anonymous', 'Use LDAPS']},
        443: {'risk': 'low', 'vulnerabilities': ['SSL/TLS vulns', 'Weak ciphers'], 'recommendations': ['Strong ciphers', 'Valid certificates']},
        445: {'risk': 'critical', 'vulnerabilities': ['EternalBlue', 'SMB exploits'], 'recommendations': ['Patch immediately', 'Network isolation']},
        1433: {'risk': 'high', 'vulnerabilities': ['SQL injection', 'Brute force'], 'recommendations': ['Strong passwords', 'Network restrictions']},
        3306: {'risk': 'high', 'vulnerabilities': ['MySQL exploits', 'Weak passwords'], 'recommendations': ['Change defaults', 'Network binding']},
        3389: {'risk': 'high', 'vulnerabilities': ['RDP brute force', 'BlueKeep'], 'recommendations': ['NLA enable', 'Strong passwords']},
        5432: {'risk': 'medium', 'vulnerabilities': ['PostgreSQL exploits', 'Weak auth'], 'recommendations': ['Strong passwords', 'Network restrictions']},
        5900: {'risk': 'high', 'vulnerabilities': ['VNC brute force', 'No encryption'], 'recommendations': ['Strong passwords', 'VPN tunnel']}
    }
    
    return security_db.get(port, {
        'risk': 'unknown',
        'vulnerabilities': ['Unknown service vulnerabilities'],
        'recommendations': ['Research service security', 'Apply patches']
    }) 