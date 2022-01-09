# Log4jScanner
Log4jScanner is a Log4j Related CVEs Scanner, Designed to Help Penetration Testers to Perform Black Box Testing on given subdomains.

## Features
* Fast & MultiThreaded
* Scan for Log4j RCE (CVE-2021-44228, CVE-2021-45046) 
* Over 30 Obfuscated Log4j Payload
* Mainly Designed for Mass Scale Bug Bounty
* Available Scan Type: Basic Scan & Full Scan
    - In Basic Scan, Only 1 Basic Log4Shell Payload is used for testing web app
    - In Full Scan, All Available Log4Shell Payloads are used
* Log4jScanner Fuzz all the potential endpoints such as 
    - HTTP Headers 
    - GET Based Parameter                       + Without Malicious Headers
    - POST Based Paramter with JSON Body        + Without Malicious Headers
    - POST Based Paramater with Post Parameters + Without Malicious Headers
    - GET Based Parameter                       + With Malicious Headers 
    - POST Based Paramter with JSON Body        + With Malicious Headers
    - POST Based Paramater with Post Parameters + With Malicious Headers

* Log4jScanner Also tries to Fuzz Possible POST Parameters such as:
    - Feel FREE to Add/Remove any POST Parameter
```
["username", "user", "email", "email_address", "password", "id", "action", "page", "q", "submit", "token", "data", "order", "lang", "search", "redirect", "country", "hidden"]
```

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



