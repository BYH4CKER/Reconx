#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Probe Modülü
HTTP/HTTPS sunucu bilgileri, header analizi ve dizin taraması
"""

import requests
import urllib3
from urllib.parse import urljoin, urlparse
import ssl
import socket
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.formatter import print_success, print_error, print_info, print_result

# SSL uyarılarını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def probe_http(target, timeout=5, ports=[80, 443, 8080, 8443]):
    """
    HTTP probe fonksiyonu
    
    Args:
        target (str): Hedef IP veya domain
        timeout (int): Timeout süresi
        ports (list): Test edilecek portlar
        
    Returns:
        dict: HTTP probe sonuçları
    """
    results = {
        'target': target,
        'services': [],
        'vulnerabilities': [],
        'status': 'success'
    }
    
    services_found = False
    
    for port in ports:
        print_info(f"Checking port {port} for HTTP service...")
        
        # Try HTTP and HTTPS
        schemes = ['http'] if port not in [443, 8443] else ['https']
        if port in [443, 8443]:
            schemes = ['https', 'http']
        elif port in [80, 8080]:
            schemes = ['http', 'https']
        
        for scheme in schemes:
            url = f"{scheme}://{target}:{port}"
            service_info = probe_single_service(url, timeout)
            
            if service_info:
                services_found = True
                results['services'].append(service_info)
                
                # Check common paths
                common_paths = check_common_paths(url, timeout)
                service_info['common_paths'] = common_paths
                
                # Check security headers
                security_issues = check_security_headers(service_info.get('headers', {}))
                if security_issues:
                    results['vulnerabilities'].extend(security_issues)
    
    if not services_found:
        results['status'] = 'failed'
        print_error("No HTTP service found")
    else:
        print_success(f"HTTP analysis completed: {len(results['services'])} services discovered")
    
    return results

def probe_single_service(url, timeout):
    """
    Tek bir HTTP servisini test et
    
    Args:
        url (str): Test edilecek URL
        timeout (int): Timeout süresi
        
    Returns:
        dict: Servis bilgileri veya None
    """
    try:
        print_info(f"Testing: {url}")
        
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={'User-Agent': 'ReconX Security Scanner 1.0'}
        )
        
        service_info = {
            'url': url,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds(),
            'redirects': len(response.history),
            'final_url': response.url,
            'title': extract_title(response.text),
            'server_info': {}
        }
        
        # Server bilgileri
        server = response.headers.get('Server', 'Unknown')
        powered_by = response.headers.get('X-Powered-By', '')
        
        service_info['server_info'] = {
            'server': server,
            'powered_by': powered_by,
            'php_version': extract_php_version(response.headers),
            'apache_version': extract_apache_version(server),
            'nginx_version': extract_nginx_version(server)
        }
        
        print_success(f"HTTP service found: {url}")
        print_result("Status Code", response.status_code)
        print_result("Server", server)
        if powered_by:
            print_result("X-Powered-By", powered_by)
        print_result("Content-Length", len(response.content))
        print_result("Response Time", f"{response.elapsed.total_seconds():.2f}s")
        
        return service_info
        
    except requests.exceptions.SSLError:
        print_error(f"SSL error: {url}")
    except requests.exceptions.ConnectionError:
        print_error(f"Connection error: {url}")
    except requests.exceptions.Timeout:
        print_error(f"Timeout: {url}")
    except Exception as e:
        print_error(f"HTTP probe error {url}: {str(e)}")
    
    return None

def check_common_paths(base_url, timeout):
    """
    Yaygın dizinleri ve dosyaları kontrol et
    
    Args:
        base_url (str): Ana URL
        timeout (int): Timeout süresi
        
    Returns:
        list: Bulunan path'ler
    """
    common_paths = [
        'robots.txt', 'sitemap.xml', '.htaccess', '.git/', '.svn/',
        'admin/', 'admin.php', 'administrator/', 'login/', 'login.php',
        'wp-admin/', 'wp-login.php', 'phpmyadmin/', 'cpanel/',
        'webmail/', 'mail/', 'test/', 'demo/', 'backup/',
        'config.php', 'config.inc.php', 'configuration.php',
        'info.php', 'phpinfo.php', 'server-status', 'server-info'
    ]
    
    found_paths = []
    
    print_info("Checking common paths...")
    
    for path in common_paths:
        url = urljoin(base_url, path)
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'ReconX Security Scanner 1.0'}
            )
            
            if response.status_code in [200, 301, 302, 403]:
                path_info = {
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                }
                found_paths.append(path_info)
                
                status_color = "green" if response.status_code == 200 else "yellow"
                print_success(f"Path found: {path} (Status: {response.status_code})")
                
        except Exception:
            # Sessiz geç
            pass
    
    return found_paths

def check_security_headers(headers):
    """
    Güvenlik header'larını kontrol et ve eksiklikleri belirle
    
    Args:
        headers (dict): HTTP header'lar
        
    Returns:
        list: Güvenlik problemleri
    """
    vulnerabilities = []
    
    security_headers = {
        'X-Frame-Options': 'Missing clickjacking protection',
        'X-XSS-Protection': 'Missing XSS protection',
        'X-Content-Type-Options': 'Missing MIME type sniffing protection',
        'Strict-Transport-Security': 'Missing HSTS protection',
        'Content-Security-Policy': 'Missing CSP protection'
    }
    
    for header, description in security_headers.items():
        if header not in headers:
            vulnerability = {
                'type': 'missing_security_header',
                'header': header,
                'description': description,
                'severity': 'medium'
            }
            vulnerabilities.append(vulnerability)
            print_error(f"Security vulnerability: {description}")
    
    # Server information disclosure
    server = headers.get('Server', '')
    if server and any(version in server.lower() for version in ['apache/2.', 'nginx/1.', 'microsoft-iis']):
        vulnerability = {
            'type': 'server_version_disclosure',
            'description': f'Server version information disclosed: {server}',
            'severity': 'low'
        }
        vulnerabilities.append(vulnerability)
        print_error(f"Information disclosure: Server version exposed")
    
    return vulnerabilities

def extract_title(html_content):
    """HTML title etiketini çıkar"""
    try:
        import re
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
    except Exception:
        pass
    return ""

def extract_php_version(headers):
    """PHP versiyonunu header'lardan çıkar"""
    php_version = headers.get('X-Powered-By', '')
    if 'PHP' in php_version:
        return php_version
    return ""

def extract_apache_version(server_header):
    """Apache versiyonunu çıkar"""
    if 'Apache' in server_header:
        return server_header
    return ""

def extract_nginx_version(server_header):
    """Nginx versiyonunu çıkar"""
    if 'nginx' in server_header:
        return server_header
    return "" 