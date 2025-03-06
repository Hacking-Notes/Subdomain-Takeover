import argparse
import requests
import re
from urllib.parse import urlparse
import dns.resolver
import socket
import time
from concurrent.futures import ThreadPoolExecutor
import threading
import os
import tldextract

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Wordlist paths configuration
WORDLISTS = {
    'fast': '/home/lxc/Documents/pentest/make/sub-takeover/wordlist/fast-subdomain.txt',  
    'normal': '/home/lxc/Documents/pentest/make/sub-takeover/wordlist/normal-subdomain.txt', 
    'deep': '/home/lxc/Documents/pentest/make/sub-takeover/wordlist/deep-subdomain.txt'    
}

def select_wordlist():
    """Prompt user to select a wordlist"""
    print(f"\n{Colors.BOLD}Select wordlist type:{Colors.ENDC}")
    print(f"1. Fast     ({Colors.YELLOW}~1000 words{Colors.ENDC})")
    print(f"2. Normal   ({Colors.YELLOW}~10000 words{Colors.ENDC}) [Default]")
    print(f"3. Deep     ({Colors.YELLOW}~100000 words{Colors.ENDC})")
    
    choice = input(f"\nEnter your choice (1/2/3) or press Enter for Normal: ").strip()
    
    if choice == "1":
        return WORDLISTS['fast']
    elif choice == "3":
        return WORDLISTS['deep']
    else:  # Default to normal for any other input including empty
        return WORDLISTS['normal']

def get_base_domain_from_file():
    """Read the first domain from targets.txt and extract its base domain"""
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one directory and look for targets.txt
    target_file = os.path.join(os.path.dirname(script_dir), '../targets.txt')
    
    if not os.path.exists(target_file):
        print(f"{Colors.RED}Error: targets.txt file not found in the parent directory{Colors.ENDC}")
        exit(1)
        
    try:
        with open(target_file, 'r') as f:
            first_line = f.readline().strip()
            if not first_line:
                print(f"{Colors.RED}Error: targets.txt is empty{Colors.ENDC}")
                exit(1)
                
            # Use tldextract to properly handle domain extraction
            extracted = tldextract.extract(first_line)
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            
            print(f"{Colors.CYAN}Extracted base domain: {Colors.BOLD}{base_domain}{Colors.ENDC}")
            return base_domain
            
    except Exception as e:
        print(f"{Colors.RED}Error reading targets.txt: {str(e)}{Colors.ENDC}")
        exit(1)

def get_status_color(status_code):
    if status_code == 200:
        return Colors.GREEN
    elif status_code in [301, 302, 307, 308]:
        return Colors.BLUE
    elif status_code in [401, 403]:
        return Colors.YELLOW
    elif status_code in [500, 502, 503, 504]:
        return Colors.RED
    else:
        return Colors.CYAN

def extract_domains(response_data):
    domains = set()
    for cert in response_data:
        name_value = cert.get('name_value', '')
        for name in name_value.split('\n'):
            domain_match = re.match(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})*)', name)
            if domain_match:
                domains.add(domain_match.group(1))
    return domains

def search_crt_sh(domain):
    search_url = f"https://crt.sh?q=%.{domain}&output=json"
    print(f"{Colors.CYAN}Querying URL: {Colors.BOLD}{search_url}{Colors.ENDC}")
    response = requests.get(search_url)
    
    if response.status_code == 200:
        response_data = response.json()
        domains = extract_domains(response_data)
        
        if domains:
            print(f"\n{Colors.BOLD}Extracted domains:{Colors.ENDC}")
            for domain in sorted(domains):
                print(f"{Colors.GREEN}{domain}{Colors.ENDC}")
            return domains
        else:
            print(f"\n{Colors.YELLOW}No domains found.{Colors.ENDC}")
            return set()
    else:
        print(f"{Colors.RED}Failed to fetch data from crt.sh.{Colors.ENDC}")
        return set()

def check_subdomain(domain, subdomain, tried_count, total_lines):
    url = f"http://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=5)
        return f"{subdomain}.{domain}", True, response.status_code
    except requests.exceptions.RequestException:
        return None, False, None

def search_brute_force(domain, wordlist):
    found_subdomains = set()
    try:
        total_lines = sum(1 for line in open(wordlist))
    except Exception as e:
        print(f"{Colors.RED}Error reading wordlist: {str(e)}{Colors.ENDC}")
        return set()

    tried_count = 0

    print(f"\n{Colors.BOLD}Starting brute force scan with {Colors.BLUE}{total_lines}{Colors.ENDC}{Colors.BOLD} subdomains...{Colors.ENDC}\n")

    try:
        with open(wordlist, 'r') as file:
            for subdomain in file:
                subdomain = subdomain.strip()
                full_subdomain, found, status_code = check_subdomain(domain, subdomain, tried_count + 1, total_lines)

                tried_count += 1

                if found:
                    found_subdomains.add(full_subdomain)
                    status_color = get_status_color(status_code)
                    progress = f"[{tried_count}/{total_lines}]"
                    percentage = f"({int((tried_count / total_lines) * 100)}%)"
                    
                    print(
                        f"{Colors.BOLD}{full_subdomain}{Colors.ENDC} - "
                        f"{status_color}Status Code: {status_code}{Colors.ENDC} "
                        f"{Colors.CYAN}{progress} {percentage}{Colors.ENDC}"
                    )

    except Exception as e:
        print(f"{Colors.RED}Error during brute force scan: {str(e)}{Colors.ENDC}")

    return found_subdomains

def save_to_file(domains, domain, mode='w'):
    main_domain = domain.replace('www.', '')

    # Get script directory and backtrack two levels before creating 'outputs'
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(os.path.dirname(os.path.dirname(script_dir)), 'outputs')

    # Create outputs directory if it doesn't exist
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except Exception as e:
            print(f"{Colors.RED}Error creating outputs directory: {str(e)}{Colors.ENDC}")
            return

    # Construct full file path
    filename = f"subdomain-{main_domain}.txt"
    filepath = os.path.join(output_dir, filename)

    try:
        with open(filepath, mode) as f:
            for subdomain in sorted(domains):
                f.write(subdomain + "\n")
        print(f"\n{Colors.PURPLE}Subdomains saved to {Colors.BOLD}{filepath}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}Error saving to file: {str(e)}{Colors.ENDC}")

def check_takeover(domain):
    """Check domain for potential subdomain takeover vulnerabilities"""
    try:
        # Check CNAME record
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            
            # Try to get the content of the CNAME
            try:
                response = requests.get(f"http://{cname}", timeout=5)
                content = response.text.lower()
                
                # Define takeover signatures
                signatures = {
                    "heroku": ("there is no app configured at that hostname", "non-existing Heroku app"),
                    "amazonaws": ("nosuchbucket", "unclaimed AmazonAWS bucket"),
                    "squarespace": ("no such account", "non-existing SquareSpace account"),
                    "github.io": ("there isn't a github pages site here", "non-existing Github subdomain"),
                    "shopify": ("sorry, this shop is currently unavailable", "non-existing Shopify subdomain"),
                    "tumblr": ("there's nothing here", "non-existing Tumblr subdomain"),
                    "wpengine": ("the site you were looking for couldn't be found", "non-existing WPEngine subdomain")
                }
                
                # Check for signatures
                for service, (signature, message) in signatures.items():
                    if signature in content.lower():
                        print(f"{Colors.RED}- Subdomain pointing to a {message} showing: {signature}{Colors.ENDC}")
                        return True
                
                print(f"{Colors.YELLOW}- Seems like {domain} is an alias for {cname}{Colors.ENDC}")
                
            except requests.RequestException:
                pass
                
        except dns.resolver.NoAnswer:
            pass
            
        # Get IP address
        try:
            ip_address = socket.gethostbyname(domain)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            
            response = requests.get(f"http://{domain}", timeout=5)
            status_code = response.status_code
            
            print(f"{Colors.BOLD}[{timestamp}] {Colors.GREEN}{status_code} {domain} -> {ip_address}{Colors.ENDC}")
            
            if ip_address == "127.0.0.1":
                print(f"{Colors.RED}Sub domain is pointing to localhost --> Check for more details{Colors.ENDC}")
                
            if status_code == 404:
                print(f"{Colors.RED}----> Check for further information on where this is pointing to.{Colors.ENDC}")
                
        except socket.gaierror:
            pass
            
    except Exception as e:
        pass
        
    return False

def test_subdomain_takeover(domains):
    print(f"\n{Colors.BOLD}Testing for potential subdomain takeover...{Colors.ENDC}\n")
    
    # Create a thread pool to test domains concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_takeover, domains)
    print("")

def main():
    all_domains = set()
    
    # Get the base domain from targets.txt
    domain = get_base_domain_from_file()

    print(f"{Colors.BOLD}Choose a search method:{Colors.ENDC}")
    print("1. crt.sh")
    print("2. Brute force")
    print("3. Both")
    
    choice = input(f"\nEnter your choice (1/2/3): ").strip()

    if choice not in ["1", "2", "3"]:
        print(f"{Colors.RED}Invalid choice. Exiting...{Colors.ENDC}")
        return

    # Select wordlist if needed
    wordlist = None
    if choice in ["2", "3"]:
        wordlist = select_wordlist()
        if not os.path.exists(wordlist):
            print(f"{Colors.RED}Error: Wordlist not found at {wordlist}{Colors.ENDC}")
            return

    if choice == "1" or choice == "3":
        print("")
        print("===============================================")
        print(f"\n{Colors.BOLD}Running crt.sh search...{Colors.ENDC}")
        crt_domains = search_crt_sh(domain)
        all_domains.update(crt_domains)
        if choice == "1":
            save_to_file(all_domains, domain)
    
    if choice == "2" or choice == "3":
        print("")
        print("===============================================")
        print(f"\n{Colors.BOLD}Using wordlist: {Colors.CYAN}{wordlist}{Colors.ENDC}")
        brute_domains = search_brute_force(domain, wordlist)
        all_domains.update(brute_domains)
        if choice == "2":
            save_to_file(all_domains, domain)
    
    if choice == "3":
        save_to_file(all_domains, domain)

    print(f"\n{Colors.BOLD}Total unique domains found: {Colors.GREEN}{len(all_domains)}{Colors.ENDC}")

    print(f"\n{Colors.BOLD}Would you like to test for subdomain takeover? (Press Enter to continue or any other key to exit){Colors.ENDC}")
    choice = input()
    print("=================================================================================================")
    
    if choice == "":
        test_subdomain_takeover(all_domains)

if __name__ == "__main__":
    main()