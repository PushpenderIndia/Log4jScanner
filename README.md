<h1 align="center">Log4jScanner</h1>
<p align="center">
    <a href="https://python.org">
    <img src="https://img.shields.io/badge/Python-3.9-green.svg">
  </a>
  <a href="https://github.com/PushpenderIndia/Log4jScanner/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/License-GNUv3-lightgrey.svg">
  </a>
  <a href="https://github.com/PushpenderIndia/Log4jScanner/releases">
    <img src="https://img.shields.io/badge/Release-1.1-blue.svg">
  </a>
    <a href="https://github.com/PushpenderIndia/Log4jScanner">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg">
  </a>
</p>

<p align="center">
  <img src="https://github.com/PushpenderIndia/Log4jScanner/blob/3368a4679f094993189df1ba0839d03ba5cf0c11/img/Logo.PNG" alt="Log4jScanner Logo">
</p>     

Log4jScanner is a Log4j Related CVEs Scanner, Designed to Help Penetration Testers to Perform Black Box Testing on given subdomains.

## Disclaimer
<p align="center">
  :computer: This project was created only for good purposes and personal use.
</p>

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. YOU MAY USE THIS SOFTWARE AT YOUR OWN RISK. THE USE IS COMPLETE RESPONSIBILITY OF THE END-USER. THE DEVELOPERS ASSUME NO LIABILITY AND ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS PROGRAM.

## Features
- [x] Fast & MultiThreaded
- [x] Scan for Log4j RCE (CVE-2021-44228, CVE-2021-45046) 
- [x] Over 30 Obfuscated Log4j Payload
- [x] Mainly Designed for Mass Scale Bug Bounty
- [x] Available Scan Type: Basic Scan & Full Scan
    - In Basic Scan, Only 1 Basic Log4Shell Payload is used for testing web app
    - In Full Scan, All Available Log4Shell Payloads are used
- [x] Log4jScanner Fuzz all the potential endpoints such as 
    - HTTP Headers 
    - GET Based Parameter                       + Without Malicious Headers
    - POST Based Paramter with JSON Body        + Without Malicious Headers
    - POST Based Paramater with Post Parameters + Without Malicious Headers
    - GET Based Parameter                       + With Malicious Headers 
    - POST Based Paramter with JSON Body        + With Malicious Headers
    - POST Based Paramater with Post Parameters + With Malicious Headers
- [x] Log4jScanner Also tries to Fuzz Possible POST Parameters such as:
    - Feel FREE to Add/Remove any POST Parameter
```
["username", "user", "email", "email_address", "password", "id", "action", "page", "q", "submit", "token", "data", "order", "lang", "search", "redirect", "country", "hidden"]
```

## Prerequisite
- [x] Python 3.X

## Installation
* Install Python3 on your system, As Python comes preinstalled in Linux & MacOS, Simply run this pip command
* This Python Module is OS Independent, & thus you can easily install it using this pip command
```
$ python3 -m pip install Log4jScanner

OR

$ pip3 install Log4jScanner
```

## Usage 

* Type `log4jscanner -h` for help menu

![](https://github.com/PushpenderIndia/Log4jScanner/blob/main/img/Help.PNG?raw=True)

* Only `--url-list` or `--url` are mandatory parameter/flags.
* You can also import this module in your code

```
from log4jscanner import Log4jScanner

# test = Log4jScanner.Log4jScanner(file_containing_urls, url_list, ThreadNumber, timeout, custom_dns_callback_host, dns_callback_provider, disable_redirect, exclude_user_agent_fuzzing, basic_scan, file_containing_headers)
# Available Headers file path: db/headers-large.txt, db/headers-minimal.txt, db/headers.txt
# Or you can Given Full Path of File Containing HTTP Request Headers
test = Log4jScanner.Log4jScanner("", ["https://google.com"], 30, 30, "", "interact.sh", False, False, False, "db/headers.txt")
vuln_url_list = test.start()

for url in vuln_url_list:
    print(url)
```

## Usage Example
```
# Basic Recon (Passive Subdomain Enumeration)
$ subfinder -d bugcrowd.com -nC -silent -o subdomains.txt && cat subdomains.txt | httpx -nc -silent > httpx_subdomains.txt

$ log4jscanner -m httpx_subdomains.txt 
```

## Screenshots:

#### Help Menu
![](https://github.com/PushpenderIndia/Log4jScanner/blob/main/img/Help.PNG?raw=True)

#### Single URL - Basic Scan
![](https://github.com/PushpenderIndia/Log4jScanner/blob/main/img/BasicScan.PNG?raw=True)

## Link:
- [x] Documentation Link: ![Click Here](https://github.com/PushpenderIndia/Log4jScanner)
- [x] PyPi Link: ![Click Here](https://pypi.org/project/Log4jScanner)






