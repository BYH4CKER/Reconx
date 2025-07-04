#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP Tarama Modülü
FTP servis keşfi, anonymous login testi ve banner grabbing
"""

import ftplib
import socket
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.formatter import print_success, print_error, print_info, print_result

def scan_ftp(target, timeout=5, ports=[21]):
    """
    FTP tarama fonksiyonu
    
    Args:
        target (str): Hedef IP veya domain
        timeout (int): Timeout süresi
        ports (list): Test edilecek FTP portları
        
    Returns:
        dict: FTP tarama sonuçları
    """
    results = {
        'target': target,
        'services': [],
        'vulnerabilities': [],
        'status': 'success'
    }
    
    services_found = False
    
    for port in ports:
        print_info(f"Checking port {port} for FTP service...")
        
        service_info = probe_ftp_service(target, port, timeout)
        
        if service_info:
            services_found = True
            results['services'].append(service_info)
            
            # Anonymous login test
            if service_info.get('anonymous_login'):
                vulnerability = {
                    'type': 'anonymous_ftp_access',
                    'description': 'FTP anonymous access enabled',
                    'severity': 'high',
                    'port': port
                }
                results['vulnerabilities'].append(vulnerability)
                print_error("Security vulnerability: FTP anonymous access enabled!")
    
    if not services_found:
        results['status'] = 'failed'
        print_error("No FTP service found")
    else:
        print_success(f"FTP scan completed: {len(results['services'])} services discovered")
    
    return results

def probe_ftp_service(target, port, timeout):
    """
    Tek bir FTP servisini test et
    
    Args:
        target (str): Hedef IP veya domain
        port (int): FTP portu
        timeout (int): Timeout süresi
        
    Returns:
        dict: FTP servis bilgileri veya None
    """
    try:
        print_info(f"Testing FTP connection: {target}:{port}")
        
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout)
        
        # Get banner
        welcome_message = ftp.getwelcome()
        
        service_info = {
            'target': target,
            'port': port,
            'banner': welcome_message,
            'anonymous_login': False,
            'anonymous_directories': [],
            'server_type': identify_ftp_server(welcome_message),
            'features': []
        }
        
        print_success(f"FTP service found: {target}:{port}")
        print_result("Banner", welcome_message)
        print_result("Server Type", service_info['server_type'])
        
        # Try anonymous login
        anonymous_success = test_anonymous_login(ftp, service_info)
        
        ftp.quit()
        
        return service_info
        
    except ftplib.error_perm as e:
        print_error(f"FTP permission error {target}:{port}: {str(e)}")
    except ftplib.error_temp as e:
        print_error(f"FTP temporary error {target}:{port}: {str(e)}")
    except socket.timeout:
        print_error(f"FTP timeout {target}:{port}")
    except socket.error as e:
        print_error(f"FTP connection error {target}:{port}: {str(e)}")
    except Exception as e:
        print_error(f"FTP probe error {target}:{port}: {str(e)}")
    
    return None

def test_anonymous_login(ftp, service_info):
    """
    Anonymous FTP login testi
    
    Args:
        ftp: FTP bağlantı nesnesi
        service_info (dict): Servis bilgileri (güncellenecek)
        
    Returns:
        bool: Anonymous login başarılı mı
    """
    try:
        print_info("Testing anonymous FTP login...")
        
        # Try anonymous login
        ftp.login('anonymous', 'anonymous@')
        
        service_info['anonymous_login'] = True
        print_success("Anonymous FTP access successful!")
        
        # List directories
        try:
            directories = []
            file_list = ftp.nlst()
            
            for item in file_list[:10]:  # First 10 items
                try:
                    # Check if directory or file
                    current_dir = ftp.pwd()
                    ftp.cwd(item)
                    directories.append({
                        'name': item,
                        'type': 'directory'
                    })
                    ftp.cwd(current_dir)
                except:
                    directories.append({
                        'name': item,
                        'type': 'file'
                    })
            
            service_info['anonymous_directories'] = directories
            
            print_info("Anonymous FTP directory listing:")
            for item in directories:
                print_result(item['type'].capitalize(), item['name'])
                
        except Exception as e:
            print_error(f"FTP directory listing error: {str(e)}")
        
        return True
        
    except ftplib.error_perm as e:
        if "530" in str(e):  # Login incorrect
            print_info("Anonymous FTP access disabled")
        else:
            print_error(f"Anonymous FTP test error: {str(e)}")
        return False
    except Exception as e:
        print_error(f"Anonymous FTP test error: {str(e)}")
        return False

def identify_ftp_server(banner):
    """
    FTP sunucu türünü banner'dan belirle
    
    Args:
        banner (str): FTP welcome mesajı
        
    Returns:
        str: Sunucu türü
    """
    banner_lower = banner.lower()
    
    server_signatures = {
        'vsftpd': 'vsftpd',
        'proftpd': 'proftpd',
        'pure-ftpd': 'pure-ftpd',
        'filezilla': 'filezilla',
        'microsoft ftp': 'microsoft iis ftp',
        'wu-ftpd': 'wu-ftpd',
        'ncftpd': 'ncftpd',
        'serv-u': 'serv-u',
        'gene6': 'gene6',
        'cerberus': 'cerberus'
    }
    
    for signature, server_type in server_signatures.items():
        if signature in banner_lower:
            return server_type
    
    return "Unknown FTP Server"

def grab_ftp_banner(target, port=21, timeout=5):
    """
    Raw FTP banner grabbing
    
    Args:
        target (str): Hedef IP veya domain
        port (int): FTP portu
        timeout (int): Timeout süresi
        
    Returns:
        str: Banner veya None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner
        
    except Exception:
        return None

def test_ftp_bounce_attack(target, port=21, timeout=5):
    """
    FTP Bounce Attack testi (PORT komutu kötüye kullanımı)
    
    Args:
        target (str): Hedef IP veya domain
        port (int): FTP portu
        timeout (int): Timeout süresi
        
    Returns:
        bool: Bounce attack mümkün mü
    """
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout)
        
        # Test için sahte bir PORT komutu dene
        test_ip = "127.0.0.1"
        test_port = 80
        
        # PORT komutunu manuel gönder
        port_cmd = f"PORT {test_ip.replace('.', ',')},{test_port//256},{test_port%256}"
        
        response = ftp.sendcmd(port_cmd)
        
        ftp.quit()
        
        # 200 yanıtı bounce attack'a açık olduğunu gösterir
        return response.startswith('200')
        
    except Exception:
        return False 