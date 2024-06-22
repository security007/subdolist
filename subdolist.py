import requests
import concurrent.futures
import re
import sys
from bs4 import BeautifulSoup as bs

requests.packages.urllib3.disable_warnings()

class SubdomainScanner:
    def __init__(self, domain, wordlist_file):
        self.domain = domain
        self.headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
        with open(wordlist_file, "r") as f:
            self.wordlist = f.read().splitlines()
        self.total_words = len(self.wordlist)
        self.total_cert = 0
        self.completed = 0
        self.completed_cert = 0

    def cert(self):
        clear_domain = []
        try:
            req = requests.get(f"https://crt.sh/?q={self.domain}",headers=self.headers)
        except KeyboardInterrupt:
            sys.exit()
        except:
            req = None
        
        if req:
            domains = re.findall(r'\b(?:\w+\.)+\w+\b', req.text)
            for domain in domains:
                if "*" not in domain and domain not in clear_domain and self.domain in domain:
                    clear_domain.append(domain)
        self.total_cert += len(clear_domain)
        return clear_domain


    def scan_subdomain(self, word):
        session = requests.Session()
        word = word.strip()
        target = f"{word}.{self.domain}"
        
        try:
            req = session.get(f"https://{target}", headers=self.headers, verify=False,timeout=5)
            soup = bs(req.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No title"
            print(f"[BRUTE] https://{target.ljust(50)} :: Code: {req.status_code} :: Title: {title}")
        except KeyboardInterrupt:
            sys.exit()
        except requests.RequestException:
            pass
        self.completed += 1
        print(f":: Bruteforcing :: {self.completed}/{self.total_words} ::", end="\r", flush=True)

    def scan_form_cert(self,domain):
        session = requests.Session()
        try:
            req = session.get(f"https://{domain}", headers=self.headers, verify=False,timeout=5)
            soup = bs(req.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No title"
            print(f"[CRT.SH] https://{domain.ljust(50)} :: Code: {req.status_code} :: Title: {title}")
        except KeyboardInterrupt:
            sys.exit()
        except requests.RequestException:
            pass
        self.completed_cert += 1
        print(f":: Checking :: {self.completed_cert}/{self.total_cert} ::", end="\r", flush=True)

    def run(self):
        print(":: Checking from certificate ::")
        cert = self.cert()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
                pool.map(self.scan_form_cert, cert)
        except KeyboardInterrupt:
            sys.exit()

        print("\n")
        print(":: Checking from Wordlist ::")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
                pool.map(self.scan_subdomain, self.wordlist)
        except KeyboardInterrupt:
            sys.exit()

            

if __name__ == "__main__":
    try:
        scanner = SubdomainScanner(sys.argv[1], "list.txt")
        scanner.run()
    except KeyboardInterrupt:
        sys.exit()
    except IndexError:
        sys.exit("Usage: python subdolist.py domain.com")
