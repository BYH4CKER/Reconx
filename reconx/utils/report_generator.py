#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report Generator Module
Generate HTML and JSON reports for reconnaissance results
"""

import json
import os
from datetime import datetime
from utils.formatter import print_success, print_error, print_info

def generate_json_report(results, filename="reconx_report.json"):
    """
    Generate JSON report
    
    Args:
        results (dict): Scan results
        filename (str): Output filename
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print_success(f"JSON report generated: {filename}")
        return True
        
    except Exception as e:
        print_error(f"Failed to generate JSON report: {str(e)}")
        return False

def generate_html_report(results, filename="reconx_report.html"):
    """
    Generate HTML report
    
    Args:
        results (dict): Scan results
        filename (str): Output filename
    """
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
        
        .header .subtitle {{
            opacity: 0.9;
            margin-top: 10px;
            font-size: 1.2em;
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
        
        .port-table, .dns-table, .http-table, .ftp-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        .port-table th, .dns-table th, .http-table th, .ftp-table th {{
            background: #495057;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        .port-table td, .dns-table td, .http-table td, .ftp-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .port-table tr:nth-child(even), .dns-table tr:nth-child(even),
        .http-table tr:nth-child(even), .ftp-table tr:nth-child(even) {{
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
        
        .vulnerability.high {{
            background: #f8d7da;
            border-color: #f5c6cb;
        }}
        
        .vulnerability.medium {{
            background: #fff3cd;
            border-color: #ffeaa7;
            color: #856404;
        }}
        
        .vulnerability.low {{
            background: #d1ecf1;
            border-color: #bee5eb;
            color: #0c5460;
        }}
        
        .status-success {{
            color: #28a745;
            font-weight: bold;
        }}
        
        .status-failed {{
            color: #dc3545;
            font-weight: bold;
        }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        
        .badge-success {{
            background: #28a745;
        }}
        
        .badge-danger {{
            background: #dc3545;
        }}
        
        .badge-warning {{
            background: #ffc107;
            color: #212529;
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
            <h1>ReconX Security Report</h1>
            <div class="subtitle">Advanced Network Reconnaissance Analysis</div>
        </div>
        
        <div class="content">
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Date:</strong> {scan_time}</p>
                <p><strong>Modules Executed:</strong> {len(modules)}</p>
            </div>
    """
    
    # Add vulnerability details section first (if available)
    vuln_details = results.get('vulnerability_details', {})
    if vuln_details:
        html += generate_vulnerability_section(vuln_details)
    
    # Add module results
    for module_name, module_data in modules.items():
        if module_data:
            html += generate_module_section(module_name, module_data)
    
    html += """
        </div>
        
        <div class="footer">
            Generated by ReconX v1.2 - Advanced Network Security Discovery & Vulnerability Analysis Tool<br>
            <em>Use responsibly and only on authorized systems</em>
        </div>
    </div>
</body>
</html>
    """
    
    return html

def generate_module_section(module_name, data):
    """Generate HTML section for specific module"""
    section = f"""
    <div class="module">
        <div class="module-header">
            {module_name.replace('_', ' ').title()}
        </div>
        <div class="module-content">
    """
    
    if 'port' in module_name.lower():
        section += generate_port_section(data)
    elif 'dns' in module_name.lower():
        section += generate_dns_section(data)
    elif 'http' in module_name.lower():
        section += generate_http_section(data)
    elif 'ftp' in module_name.lower():
        section += generate_ftp_section(data)
    else:
        section += f"<pre>{json.dumps(data, indent=2)}</pre>"
    
    section += """
        </div>
    </div>
    """
    
    return section

def generate_port_section(data):
    """Generate port scan section"""
    html = ""
    
    status = data.get('status', 'unknown')
    status_class = 'status-success' if status == 'success' else 'status-failed'
    
    html += f"<p><strong>Status:</strong> <span class='{status_class}'>{status}</span></p>"
    html += f"<p><strong>Scan Type:</strong> {data.get('scan_type', 'unknown')}</p>"
    
    open_ports = data.get('open_ports', [])
    
    if open_ports:
        html += f"<h4>Open Ports ({len(open_ports)} found)</h4>"
        html += """
        <table class="port-table">
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for port in open_ports:
            html += f"""
                <tr>
                    <td>{port.get('port', '')}</td>
                    <td>{port.get('protocol', '')}</td>
                    <td><span class="badge badge-success">{port.get('state', '')}</span></td>
                    <td>{port.get('service', '')}</td>
                    <td>{port.get('version', '')}</td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
    else:
        html += "<p>No open ports detected.</p>"
    
    return html

def generate_dns_section(data):
    """Generate DNS section"""
    html = ""
    
    records = data.get('records', {})
    subdomains = data.get('subdomains', [])
    
    # DNS Records
    for record_type, record_list in records.items():
        if record_list:
            html += f"<h4>{record_type} Records</h4>"
            html += "<ul>"
            
            for record in record_list:
                if isinstance(record, dict):
                    # MX records
                    html += f"<li>{record.get('priority', '')} {record.get('exchange', '')}</li>"
                else:
                    html += f"<li>{record}</li>"
            
            html += "</ul>"
    
    # Subdomains
    if subdomains:
        html += f"<h4>Discovered Subdomains ({len(subdomains)})</h4>"
        html += """
        <table class="dns-table">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Addresses</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for subdomain in subdomains:
            ips = ', '.join(subdomain.get('ips', []))
            html += f"""
                <tr>
                    <td>{subdomain.get('subdomain', '')}</td>
                    <td>{ips}</td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
    
    return html

def generate_http_section(data):
    """Generate HTTP section"""
    html = ""
    
    services = data.get('services', [])
    vulnerabilities = data.get('vulnerabilities', [])
    
    if services:
        html += f"<h4>HTTP Services ({len(services)} found)</h4>"
        
        for service in services:
            html += f"""
            <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px;">
                <h5>{service.get('url', '')}</h5>
                <p><strong>Status Code:</strong> {service.get('status_code', '')}</p>
                <p><strong>Server:</strong> {service.get('server_info', {}).get('server', '')}</p>
                <p><strong>Response Time:</strong> {service.get('response_time', '')}s</p>
            """
            
            common_paths = service.get('common_paths', [])
            if common_paths:
                html += f"<p><strong>Discovered Paths:</strong></p><ul>"
                for path in common_paths:
                    html += f"<li>{path.get('path', '')} (Status: {path.get('status_code', '')})</li>"
                html += "</ul>"
            
            html += "</div>"
    
    # Vulnerabilities
    if vulnerabilities:
        html += f"<h4>Security Issues ({len(vulnerabilities)} found)</h4>"
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            html += f"""
            <div class="vulnerability {severity}">
                <strong>{vuln.get('type', '').replace('_', ' ').title()}:</strong>
                {vuln.get('description', '')}
            </div>
            """
    
    return html

def generate_ftp_section(data):
    """Generate FTP section"""
    html = ""
    
    services = data.get('services', [])
    vulnerabilities = data.get('vulnerabilities', [])
    
    if services:
        html += f"<h4>FTP Services ({len(services)} found)</h4>"
        
        for service in services:
            html += f"""
            <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px;">
                <h5>FTP Server - {service.get('target', '')}:{service.get('port', '')}</h5>
                <p><strong>Banner:</strong> {service.get('banner', '')}</p>
                <p><strong>Server Type:</strong> {service.get('server_type', '')}</p>
                <p><strong>Anonymous Login:</strong> 
                    <span class="badge badge-{'danger' if service.get('anonymous_login') else 'success'}">
                        {'Enabled' if service.get('anonymous_login') else 'Disabled'}
                    </span>
                </p>
            """
            
            if service.get('anonymous_directories'):
                html += "<p><strong>Anonymous Directory Listing:</strong></p><ul>"
                for item in service.get('anonymous_directories', []):
                    html += f"<li>{item.get('name', '')} ({item.get('type', '')})</li>"
                html += "</ul>"
            
            html += "</div>"
    
    # Vulnerabilities
    if vulnerabilities:
        html += f"<h4>Security Issues ({len(vulnerabilities)} found)</h4>"
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            html += f"""
            <div class="vulnerability {severity}">
                <strong>{vuln.get('type', '').replace('_', ' ').title()}:</strong>
                {vuln.get('description', '')}
            </div>
            """
    
    return html

def generate_vulnerability_section(vuln_data):
    """Generate comprehensive vulnerability analysis section"""
    html = ""
    
    total_vulns = vuln_data.get('total_vulnerabilities', 0)
    critical_count = vuln_data.get('critical_count', 0)
    high_count = vuln_data.get('high_count', 0)
    medium_count = vuln_data.get('medium_count', 0)
    low_count = vuln_data.get('low_count', 0)
    
    # Priority vulnerability section with enhanced styling
    html += f"""
    <div class="module" style="border: 3px solid #e74c3c;">
        <div class="module-header" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
            VULNERABILITY ANALYSIS - {total_vulns} TOTAL VULNERABILITIES FOUND
        </div>
        <div class="module-content">
            
            <!-- Vulnerability Summary -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px;">
                <div style="background: #e74c3c; color: white; padding: 15px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; font-size: 2em;">{critical_count}</h3>
                    <p style="margin: 5px 0 0 0;">Critical</p>
                </div>
                <div style="background: #f39c12; color: white; padding: 15px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; font-size: 2em;">{high_count}</h3>
                    <p style="margin: 5px 0 0 0;">High</p>
                </div>
                <div style="background: #f1c40f; color: #2c3e50; padding: 15px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; font-size: 2em;">{medium_count}</h3>
                    <p style="margin: 5px 0 0 0;">Medium</p>
                </div>
                <div style="background: #27ae60; color: white; padding: 15px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; font-size: 2em;">{low_count}</h3>
                    <p style="margin: 5px 0 0 0;">Low</p>
                </div>
            </div>
    """
    
    # Critical alert if high-risk vulnerabilities found
    if critical_count > 0 or high_count > 0:
        html += f"""
        <div style="background: #e74c3c; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
            <h3 style="margin: 0;">[ALERT] IMMEDIATE ACTION REQUIRED!</h3>
            <p style="margin: 10px 0 0 0; font-size: 1.1em;">
                {critical_count + high_count} Critical/High severity vulnerabilities detected that require immediate attention!
            </p>
        </div>
        """
    
    # Detailed vulnerability list
    vulnerabilities = vuln_data.get('vulnerabilities', [])
    
    if vulnerabilities:
        # Group vulnerabilities by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            by_severity[severity].append(vuln)
        
        # Display vulnerabilities by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            vulns = by_severity[severity]
            if not vulns:
                continue
            
            severity_colors = {
                'critical': '#e74c3c',
                'high': '#f39c12', 
                'medium': '#f1c40f',
                'low': '#27ae60'
            }
            
            severity_icons = {
                'critical': '💀', # Critical
                'high': '🔥',
                'medium': '⚠️',
                'low': 'ℹ️'
            }
            
            color = severity_colors[severity]
            icon = severity_icons[severity]
            text_color = 'white' if severity in ['critical', 'high', 'low'] else '#2c3e50'
            
            html += f"""
            <h3 style="color: {color}; border-bottom: 2px solid {color}; padding-bottom: 10px;">
                [{severity.upper()}] SEVERITY ({len(vulns)} vulnerabilities)
            </h3>
            """
            
            for i, vuln in enumerate(vulns, 1):
                if vuln['type'] == 'cve':
                    exploit_count = len(vuln.get('exploits', []))
                    
                    html += f"""
                    <div style="background: white; border: 2px solid {color}; border-radius: 8px; padding: 20px; margin: 15px 0; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                            <h4 style="margin: 0; color: {color}; font-size: 1.2em;">
                                {vuln.get('cve_id', 'N/A')}: {vuln.get('title', 'Unknown Vulnerability')}
                            </h4>
                            <div style="display: flex; gap: 10px;">
                                <span style="background: {color}; color: {text_color}; padding: 4px 10px; border-radius: 12px; font-size: 0.9em; font-weight: bold;">
                                    {severity.upper()}
                                </span>
                                {"<span style='background: #34495e; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.9em; font-weight: bold;'>CVSS: " + str(vuln.get('cvss', 'N/A')) + "</span>" if vuln.get('cvss') else ""}
                            </div>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px; background: #f8f9fa; padding: 15px; border-radius: 5px;">
                            <div><strong>Port:</strong> {vuln.get('port', 'N/A')}</div>
                            <div><strong>Service:</strong> {vuln.get('service', 'N/A')}</div>
                            <div><strong>Year:</strong> {vuln.get('year', 'N/A')}</div>
                            <div><strong>Exploits Available:</strong> <span style="color: {'#e74c3c' if exploit_count > 0 else '#27ae60'}; font-weight: bold;">{exploit_count}</span></div>
                        </div>
                    """
                    
                    # Show exploits if available
                    if vuln.get('exploits'):
                        html += f"""
                        <div style="background: #e8f5e8; border-radius: 5px; padding: 15px;">
                            <h5 style="margin: 0 0 10px 0; color: #27ae60;">Available Exploits:</h5>
                        """
                        
                        for exploit in vuln.get('exploits', []):
                            exploit_type = exploit.get('type', 'unknown')
                            exploit_title = exploit.get('title', 'Unknown Exploit')
                            
                            type_colors = {
                                'exploit-db': '#e74c3c',
                                'metasploit': '#9b59b6'
                            }
                            type_color = type_colors.get(exploit_type, '#34495e')
                            
                            html += f"""
                            <div style="background: white; border-left: 4px solid {type_color}; padding: 10px; margin: 8px 0; border-radius: 3px;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span><strong>{exploit_title}</strong></span>
                                    <span style="background: {type_color}; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.8em;">
                                        {exploit_type.upper()}
                                    </span>
                                </div>
                                {"<small style='color: #7f8c8d;'>Module: " + exploit.get('module', '') + "</small>" if exploit.get('module') else ""}
                            </div>
                            """
                        
                        html += "</div>"
                    
                    html += "</div>"
                
                else:  # NSE script vulnerability
                    html += f"""
                    <div style="background: white; border: 2px solid {color}; border-radius: 8px; padding: 15px; margin: 10px 0;">
                        <h4 style="margin: 0 0 10px 0; color: {color};">
                            NSE Detection: {vuln.get('title', 'Unknown')}
                        </h4>
                        <div style="background: #f8f9fa; padding: 10px; border-radius: 5px;">
                            <strong>Port:</strong> {vuln.get('port', 'N/A')} | 
                            <strong>Script:</strong> {vuln.get('script', 'N/A')}
                        </div>
                    </div>
                    """
    
    # NSE Results Summary
    nse_results = vuln_data.get('nse_results', {})
    if nse_results:
        html += f"""
        <h3 style="color: #3498db; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-top: 30px;">
            NSE SCRIPT RESULTS
        </h3>
        <p>NSE (Nmap Scripting Engine) vulnerability detection scripts were executed on {len(nse_results)} ports.</p>
        """
        
        for port, scripts in nse_results.items():
            html += f"""
            <div style="background: #f8f9fa; border-radius: 8px; padding: 15px; margin: 10px 0;">
                <h4 style="margin: 0 0 10px 0; color: #2c3e50;">Port {port} Scripts</h4>
            """
            
            for script_name, script_data in scripts.items():
                vuln_count = len(script_data.get('vulnerabilities', []))
                html += f"""
                <div style="background: white; border-left: 3px solid #3498db; padding: 10px; margin: 5px 0;">
                    <strong>{script_name}</strong>
                    {"<span style='color: #e74c3c; margin-left: 10px;'>(" + str(vuln_count) + " vulnerabilities detected)</span>" if vuln_count > 0 else ""}
                </div>
                """
            
            html += "</div>"
    
    html += """
        </div>
    </div>
    """
    
    return html 