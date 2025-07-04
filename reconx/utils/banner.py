#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Banner ve başlangıç ekranı
"""

from colorama import Fore, Back, Style

def show_banner():
    """Display ReconX banner"""
    banner = f"""
{Fore.RED}
 ██▀▀▀██  ▄██▀▀▀██▄  ▄██▀▀▀██▄ ███▄   █ █     █
 ██   ██ ██▀     ▀██ ██▀     ▀█  ██▀█  █  █   █ 
 ██▀▀▀█▀ ██▀▀▀▀▀▀▀██ ██▀        ██ ▀█ █   █ █  
 ██   ██ ██▄     ▄██ ██▄     ▄█  ██  ▀██   ███   
 ██   ██  ▀██▄▄▄██▀   ▀██▄▄▄██▀ ████  ██    █    
{Style.RESET_ALL}
{Fore.CYAN}        Extended Reconnaissance Tool v1.0{Style.RESET_ALL}
{Fore.WHITE}     Advanced Network Security Discovery & Analysis{Style.RESET_ALL}
{Fore.YELLOW}              Developed by CyberSec Research Team{Style.RESET_ALL}
{Fore.GREEN}                   github.com/reconx-project{Style.RESET_ALL}

"""
    print(banner) 