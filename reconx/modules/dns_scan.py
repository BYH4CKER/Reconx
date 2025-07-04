#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Tarama Modülü
A, MX, TXT, NS kayıtlarını sorgular ve subdomain taraması yapar
"""

import dns.resolver
import dns.exception
import socket
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.formatter import print_success, print_error, print_info, print_result

def scan_dns(target, timeout=5):
    """
    DNS tarama fonksiyonu
    
    Args:
        target (str): Hedef domain
        timeout (int): Timeout süresi
        
    Returns:
        dict: DNS tarama sonuçları
    """
    results = {
        'target': target,
        'records': {
            'A': [],
            'MX': [],
            'TXT': [],
            'NS': []
        },
        'subdomains': [],
        'status': 'success'
    }
    
    # DNS çözümleyici ayarla
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    # Kayıt türleri
    record_types = ['A', 'MX', 'TXT', 'NS']
    
    for record_type in record_types:
        try:
            print_info(f"Querying {record_type} records...")
            answers = resolver.resolve(target, record_type)
            
            for rdata in answers:
                if record_type == 'A':
                    results['records']['A'].append(str(rdata))
                    print_result("A Record", str(rdata))
                elif record_type == 'MX':
                    results['records']['MX'].append({
                        'priority': rdata.preference,
                        'exchange': str(rdata.exchange)
                    })
                    print_result("MX Record", f"{rdata.preference} {rdata.exchange}")
                elif record_type == 'TXT':
                    txt_record = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                    results['records']['TXT'].append(txt_record)
                    print_result("TXT Record", txt_record)
                elif record_type == 'NS':
                    results['records']['NS'].append(str(rdata))
                    print_result("NS Record", str(rdata))
                    
        except dns.resolver.NXDOMAIN:
            print_error(f"{record_type} record not found (NXDOMAIN)")
        except dns.resolver.NoAnswer:
            print_error(f"No answer for {record_type} record")
        except dns.exception.Timeout:
            print_error(f"{record_type} query timed out")
        except Exception as e:
            print_error(f"{record_type} query error: {str(e)}")
    
    # Subdomain enumeration
    print_info("Starting subdomain enumeration...")
    subdomains = discover_subdomains(target, resolver, timeout)
    results['subdomains'] = subdomains
    
    if not any(results['records'].values()) and not subdomains:
        results['status'] = 'failed'
        print_error("No DNS records found")
    else:
        print_success(f"DNS scan completed: {len(subdomains)} subdomains discovered")
    
    return results

def discover_subdomains(target, resolver, timeout):
    """
    Dahili wordlist ile subdomain keşfi
    
    Args:
        target (str): Ana domain
        resolver: DNS çözümleyici
        timeout (int): Timeout süresi
        
    Returns:
        list: Bulunan subdomain'ler
    """
    subdomains_found = []
    
    # Dahili subdomain wordlist
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev',
        'staging', 'test', 'demo', 'admin', 'blog', 'shop', 'forum', 'api', 'cdn',
        'vpn', 'remote', 'secure', 'portal', 'support', 'help', 'docs', 'wiki',
        'git', 'svn', 'jenkins', 'mysql', 'phpmyadmin', 'webmin', 'controlpanel',
        'beta', 'alpha', 'sub', 'subdomain', 'database', 'db', 'old', 'new',
        'backup', 'bak', 'archive', 'store', 'download', 'upload', 'media',
        'img', 'static', 'assets', 'files', 'download', 'ftp2', 'ssh'
    ]
    
    # Load external wordlist file if exists
    wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'subdomains.txt')
    if os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                file_subdomains = [line.strip() for line in f if line.strip()]
                common_subdomains.extend(file_subdomains)
        except Exception as e:
            print_error(f"Could not read wordlist file: {str(e)}")
    
    print_info(f"Testing {len(common_subdomains)} subdomains...")
    
    for subdomain in common_subdomains:
        full_domain = f"{subdomain}.{target}"
        try:
            answers = resolver.resolve(full_domain, 'A')
            ip_addresses = [str(rdata) for rdata in answers]
            
            subdomain_info = {
                'subdomain': full_domain,
                'ips': ip_addresses
            }
            subdomains_found.append(subdomain_info)
            print_success(f"Subdomain found: {full_domain} -> {', '.join(ip_addresses)}")
            
        except dns.resolver.NXDOMAIN:
            # Subdomain not found, normal
            pass
        except dns.exception.Timeout:
            print_error(f"Subdomain query timeout: {full_domain}")
        except Exception as e:
            # Silent pass for other errors
            pass
    
    return subdomains_found

def reverse_dns_lookup(ip_address, timeout=5):
    """
    Ters DNS sorgusu
    
    Args:
        ip_address (str): IP adresi
        timeout (int): Timeout süresi
        
    Returns:
        str: Hostname veya None
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return None 