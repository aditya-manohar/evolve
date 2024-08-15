import os
import sys
import threading
import time
import requests
import pyfiglet
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import socket
import shutil
import urllib.parse
import whois
from zxcvbn import zxcvbn

init(autoreset=True)

loading = False

os.system("title evolve")

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
                if response.status_code == 200 and "error" not in response.text.lower():
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

                if response.status_code == 200:
                    if payload in response.text or "alert(1)" in response.text:
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
            "| ls"
        ]
        
        print("\nTesting for Command Injection...")
        found_vulnerability = False
        severity = "None"
        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)
                if response.status_code == 200 and any(indicator in response.text.lower() for indicator in ["root:", "bin/bash", "usr"]):
                    severity = "High"
                    print(f"{Fore.RED}Potential Command Injection vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                    found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")
        
        if not found_vulnerability:
            print(f"\n{Fore.GREEN}No Command Injection vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Command Injection severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}Command Injection testing completed.")

    def test_open_ports(self):
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

def sys_scan():
    print(Fore.GREEN+"Scanning the system for malicious files and software...\n")

    malicious_files = []
    suspicious_extensions = ['.bat', '.vbs', '.scr', '.pif', '.com']
    
    excluded_directories = [
        'C:\\Windows', 
        'C:\\Program Files', 
        'C:\\Program Files (x86)',
        'C:\\ProgramData',
        'C:\\Users\\Public'
    ]

    for root, dirs, files in os.walk('C:\\'):  
        if any(root.startswith(excluded_dir) for excluded_dir in excluded_directories):
            continue
        
        for file in files:
            file_path = os.path.join(root, file)
            truncated_path = (file_path[:75] + '...') if len(file_path) > 75 else file_path
            print(f"Scanning: {truncated_path}", end='\r', flush=True) 

            if any(file.endswith(ext) for ext in suspicious_extensions):
                malicious_files.append(file_path)
    
    print(Fore.GREEN+"\n\nScan complete!")

    if malicious_files:
        print("\nPotential malicious files found:")
        for file in malicious_files:
            print(file)
    else:
        print("\nNo malicious files found.")

def love_art(evolve_art):
    terminal_width = shutil.get_terminal_size().columns
    lines = evolve_art.splitlines()
    centered_lines = []
    for line in lines:
        centered_line = line.center(terminal_width)
        centered_lines.append(centered_line)
    return "\n".join(centered_lines)


def loading_animation(task_description):
    animation = "|/-\\"
    idx = 0
    global loading
    while loading:
        print(f"\r{Fore.CYAN}{task_description} {animation[idx % len(animation)]}{Style.RESET_ALL}", end="")
        idx += 1
        time.sleep(0.1)

def evolve_search(name):
    query = (f'"{name}" site:instagram.com OR site:facebook.com OR filetype:pdf  OR filetype:xls OR filetype:csv OR filetype:docx ')
    encoded_query = urllib.parse.quote(query)
    url = f"https://www.google.com/search?q={encoded_query}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        links = []
        for item in soup.find_all('h3'):
            link = item.find_parent('a')['href']
            links.append(link)
        return links
    else:
        print(Fore.RED + "Error: Unable to retrieve search results." + Style.RESET_ALL)
        return []
    
def search_web(query):
    encoded_query = urllib.parse.quote(query)
    url = f"https://www.google.com/search?q={encoded_query}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() 

        soup = BeautifulSoup(response.text, 'html.parser')
        results = []
        search_results = soup.find_all('div', class_='tF2Cxc')

        if not search_results:
            search_results = soup.find_all('div', class_='g')

        for item in search_results:
            title = item.find('h3').text if item.find('h3') else 'No title'
            link = item.find('a')['href'] if item.find('a') else 'No link'
            summary = 'No summary available'

            summary_tag = item.find('span', class_='aCOpRe') or item.find('div', class_='IsZvec') or item.find('div', class_='VwiC3b')
            if summary_tag:
                summary = summary_tag.text

            results.append({'title': title, 'link': link, 'summary': summary})

        if not results:
            print(Fore.RED + "No results found." + Style.RESET_ALL)
        
        return results

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error: Could not complete the search. {str(e)}" + Style.RESET_ALL)
        return []
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
        return []

def run_script(script_path):
    """Execute a Python or batch script."""
    if not os.path.exists(script_path):
        print(Fore.RED + f"Error: The script '{script_path}' does not exist." + Style.RESET_ALL)
        return

    if script_path.endswith('.py'):
        os.system(f'python "{script_path}"')
    elif script_path.endswith('.bat'):
        os.system(f'"{script_path}"')
    else:
        print(Fore.RED + "Error: Only python and batch scripts are supported for now." + Style.RESET_ALL)

def ip_geolocation(ip_address):
    token = 'e014091be9f321'
    url = f"https://ipinfo.io/{ip_address}?token={token}"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        country = data.get("country", "N/A")
        city = data.get("city", "N/A")
        isp = data.get("org", "N/A")
        
        print(f"IP Address: {ip_address}")
        print(f"Country: {country}")
        print(f"City: {city}")
        print(f"ISP: {isp}")
    else:
        print(Fore.RED + "Error retrieving geolocation data." + Style.RESET_ALL)

def check_password_strength(password):
    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']['suggestions']
    cracked_time = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    strength_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    strength_level = strength_levels[score]
    return strength_level, feedback, cracked_time
 

def display_help():
    help_text = """

       Commands:
       
     ---|-------------------------------------------------------------------------------------|---
        | run websec          : Launches the WebSec security testing tool.                    |
        | sys scan            : Scans the system for malicious files and software.            |
        | run hunter          : Search for a person online and relevant information.          |
        | search web          : Searches the web for specified keywords and returns a summary.|
        | run script <script> : Executes a specified Python or Batch script directly.         |
        | cipher <password>   : Evaluates the strength of the provided password.              |
        | geo <ip_address>    : Provides geographical information about an IP address.        |
        | calc                : Performs basic calculations.                                  |
        | clear               : Clears the command line screen.                               |
        | exit                : Exits the evolve tool.                                        |
     ---|-------------------------------------------------------------------------------------|---

    """
    print(Fore.LIGHTGREEN_EX + help_text + Style.RESET_ALL)


def main():
    print("\n")
    custom_art = """
▓█████ ██▒   █▓ ▒█████   ██▓  ██▒   █▓▓█████ 
▓█   ▀▓██░   █▒▒██▒  ██▒▓██▒ ▓██░   █▒▓█   ▀ 
▒███   ▓██  █▒░▒██░  ██▒▒██░  ▓██  █▒░▒███   
▒▓█  ▄  ▒██ █░░▒██   ██░▒██░   ▒██ █░░▒▓█  ▄ 
░▒████▒  ▒▀█░  ░ ████▓▒░░██████▒▒▀█░  ░▒████▒
░░ ▒░ ░  ░ ▐░  ░ ▒░▒░▒░ ░ ▒░▓  ░░ ▐░  ░░ ▒░ ░
 ░ ░  ░  ░ ░░    ░ ▒ ▒░ ░ ░ ▒  ░░ ░░   ░ ░  ░
   ░       ░░  ░ ░ ░ ▒    ░ ░     ░░     ░   
   ░  ░     ░      ░ ░      ░  ░   ░     ░  ░
           ░                      ░          
    """
    screen_width = os.get_terminal_size().columns
    lines = custom_art.strip().split('\n')
    for line in lines:
        print(Fore.LIGHTBLUE_EX + line.center(screen_width) + Style.RESET_ALL)
    print(Fore.GREEN + "[+] " + Fore.YELLOW + "Tool created by Aditya Manohar" + Style.RESET_ALL)


    evolve__art = """
            _______________                        |*\_/*|________
            |  ___________  |     .-.     .-.      ||_/-\_|______  |
            | |           | |    .****. .****.     | |           | |
            | |   0   0   | |    .*****.*****.     | |   0   0   | |
            | |     -     | |     .*********.      | |     -     | |
            | |   \___/   | |      .*******.       | |   \___/   | |
            | |___     ___| |       .*****.        | |___________| |
            |_____|\_/|_____|        .***.         |_______________|
                _|__|/ \\|_|_.............*.............._|________|_
            / ********** \\                          / ********** \\
            /  ************  \\                      /  ************  \\
            --------------------                    --------------------
"""

    global loading
    while True:
        command = input(Fore.GREEN + "\nevolve>> " + Style.RESET_ALL).strip().lower()

        if command == "run websec":
            tester = WebSec("http://example.com")
            tester.print_custom_art()
            url = input(Fore.YELLOW + "Enter the target URL: " + Style.RESET_ALL)
            tester = WebSec(url)

            loading = True
            loading_thread = threading.Thread(target=loading_animation, args=("Retrieving WHOIS information...",))
            loading_thread.start()
            tester.get_whois_info()
            loading = False
            loading_thread.join()
            time.sleep(0.5)

            loading = True
            loading_thread = threading.Thread(target=loading_animation, args=("Scanning for open ports...",))
            loading_thread.start()
            tester.test_open_ports()
            loading = False
            loading_thread.join() 
            time.sleep(0.5)

            loading = True
            threading.Thread(target=loading_animation, args=("Testing for SQL Injection...",)).start()
            tester.test_sql_injection()
            loading = False
            time.sleep(0.5)
    
            loading = True
            threading.Thread(target=loading_animation, args=("Testing for XSS...",)).start()
            tester.test_xss()
            loading = False
            time.sleep(0.5)

            loading = True
            threading.Thread(target=loading_animation, args=("Testing for CSRF...",)).start()
            tester.test_csrf()
            loading = False
            time.sleep(0.5)
        
            loading = True
            threading.Thread(target=loading_animation, args=("Testing for Command Injection...",)).start()
            tester.test_command_injection()
            loading = False
            time.sleep(0.5)

        elif command == "sys scan":
            sys_scan()

        elif command == "run hunter":
            print(Fore.GREEN+"""
                                    ██   ██ ██    ██ ███    ██ ████████ ███████ ██████  
                                    ██   ██ ██    ██ ████   ██    ██    ██      ██   ██ 
                                    ███████ ██    ██ ██ ██  ██    ██    █████   ██████  
                                    ██   ██ ██    ██ ██  ██ ██    ██    ██      ██   ██ 
                                    ██   ██  ██████  ██   ████    ██    ███████ ██   ██
                  """)
            name = input("Enter the name : ")
            results = evolve_search(name)
            print(Fore.GREEN+"Search Results : "+Style.RESET_ALL)
            for link in results:
                print(Fore.LIGHTCYAN_EX+" * ",link)

        elif command == "search web":
            query = input("What should I search for : ")
            results = search_web(query)
            print(Fore.GREEN + "Search Results : "+Style.RESET_ALL)
            for summary in results:
                print(summary)

        elif command.startswith("run script"):
            script_path = command[len("run script "):].strip()
            run_script(script_path)

        elif command.startswith("geo "):
            ip = command.split(" ",1)[1]
            ip_geolocation(ip)

        elif command.startswith("cipher"):
            password = command[len("cipher"):].strip()
            if password:
                strength_level, feedback, cracked_time = check_password_strength(password)
                print(Fore.GREEN + f"Password Strength: {strength_level}" + Style.RESET_ALL)
                print(Fore.YELLOW + f"Crack Time: {cracked_time}" + Style.RESET_ALL)
                if feedback:
                    print(Fore.RED + "Suggestions:" + Style.RESET_ALL)
                    for suggestion in feedback:
                        print(f"{suggestion}")
            else:
                print(Fore.RED + "Error: No password provided." + Style.RESET_ALL)

        elif command == "calc":
            while True:
                expression = input(Fore.GREEN + "calc>>" + Style.RESET_ALL)

                if expression.lower() == "exit":
                    break

                try:
                    result = eval(expression)
                    print(Fore.CYAN + f"{result}"+Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + "Enter valid input for calculation")

        elif command == "who are you":
            print("I'm evolve :)")

        elif command == "love" or command == "evol":
            print(evolve__art)

        elif command == "evolve":
            screen_width = os.get_terminal_size().columns
            lines = custom_art.strip().split('\n')
            for line in lines:
                print(Fore.LIGHTBLUE_EX + line.center(screen_width) + Style.RESET_ALL)

        elif command == "help":
            display_help()

        elif command == "evolve --help":
            display_help()

        elif command == "clear":
            os.system('cls')
        
        elif command == "exit":
            sys.exit()
        
        else:
            exit_code = os.system(command)
            if exit_code != 0 :
                print(Fore.RED + f"{command} not found. Try evolve --help")

if __name__ == "__main__":
    main()
