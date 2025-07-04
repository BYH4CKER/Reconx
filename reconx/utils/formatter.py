#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Çıktı formatlayıcı fonksiyonlar
"""

from colorama import Fore, Back, Style
import sys

def print_success(message):
    """Print success message (green)"""
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message (red)"""
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}", file=sys.stderr)

def print_warning(message):
    """Print warning message (yellow)"""
    print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message (blue)"""
    print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

def print_debug(message):
    """Print debug message (magenta)"""
    print(f"{Fore.MAGENTA}[DEBUG] {message}{Style.RESET_ALL}")

def print_result(key, value, color=Fore.GREEN):
    """Print key-value pair"""
    print(f"{Fore.WHITE}    {key}: {color}{value}{Style.RESET_ALL}")

def print_section(title):
    """Print section header"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{Style.RESET_ALL}") 