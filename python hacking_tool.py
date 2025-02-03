import requests
import time
import sys
from termcolor import colored

# ───────────────[ 🔥 GOD-LEVEL VVIP TOOL 🔥 ]───────────────
# 🔰 SECURE TOOL BY ILEE TEAM 🔰
# 📢 Join our WhatsApp Channel: https://whatsapp.com/channel/0029Vb2cnIRJpe8ZCepRYl0E
# 🚀 Elite Cyber Security | Premium Web Scanner | No Mercy Mode
# ────────────────────────────────────────────────────────

# 🔹 Color Definitions
red = '\033[91m'
green = '\033[92m'
yellow = '\033[93m'
blue = '\033[94m'
magenta = '\033[95m'
cyan = '\033[96m'
white = '\033[97m'
reset = '\033[0m'

# 🔒 Password Protection
correct_password = "demon09@"

print(f"{magenta}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
print(f"{cyan} 🔥 WELCOME TO ILEE TEAM GOD-LEVEL TOOL 🔥 {reset}")
print(f"{yellow}📢 JOIN NOW: {cyan}https://whatsapp.com/channel/0029Vb2cnIRJpe8ZCepRYl0E{reset}")
print(f"{magenta}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")

user_input = input(f"{magenta}[🔐]{reset} Enter Password to Unlock the Ultimate Power: ")

if user_input != correct_password:
    print(f"{red}[❌] ACCESS DENIED! WRONG PASSWORD.{reset}")
    sys.exit()

print(f"{green}[✅] ACCESS GRANTED! Welcome to ILEE TEAM's Ultra-VIP Tool.{reset}")
time.sleep(1)

# 🔹 Function Definitions
def send_http_request(url, method='GET', headers=None, cookies=None, proxy=None, timeout=5):
    if headers is None:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}

    try:
        if method.upper() == 'GET':
            return requests.get(url, headers=headers, cookies=cookies, proxies=proxy, timeout=timeout)
        elif method.upper() == 'POST':
            return requests.post(url, headers=headers, cookies=cookies, proxies=proxy, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"{red}[❌] Request Failed: {e}{reset}")
        return None

# 🔹 Tools Menu
def tools():
    print(f"{cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
    print(f"{yellow} 🚀 ULTRA VVIP CYBER TOOLS 🚀{reset}")
    print(f"{cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
    
    # Updated list with 100 tools
    tool_list = [
        ('[01] DNS-Lookup', '/dns-lookup'),
        ('[02] WHOIS-Lookup', '/whois'),
        ('[03] Ping-Test', '/ping'),
        ('[04] Traceroute', '/traceroute'),
        ('[05] Port-Scanning', '/ports'),
        ('[06] Web-Scraping', '/scrape'),
        ('[07] Cookie-Stealing', '/cookie'),
        ('[08] CSRF-Test', '/csrf'),
        ('[09] SQL-Injection', '/sqli'),
        ('[10] Cross-Site-Scripting (XSS)', '/xss'),
        ('[11] Brute-Force-Login', '/bruteforce'),
        ('[12] Remote-File-Inclusion (RFI)', '/rfi'),
        ('[13] Local-File-Inclusion (LFI)', '/lfi'),
        ('[14] Directory-Listing', '/listing'),
        ('[15] File-Upload', '/upload'),
        ('[16] Cron-Job-Finding', '/cron'),
        ('[17] Backdoor-Testing', '/backdoor'),
        ('[18] Version-Scanning', '/version'),
        ('[19] Exploit-Testing', '/exploit'),
        ('[20] Passive-Scanning', '/passive'),
        ('[21] Web Shell Upload', '/webshell-upload'),
        ('[22] Password Cracking', '/password-crack'),
        ('[23] Session Hijacking', '/session-hijack'),
        ('[24] Cross-Site Request Forgery', '/csrf-exploit'),
        ('[25] SSRF (Server-Side Request Forgery)', '/ssrf-exploit'),
        ('[26] Directory Traversal', '/dir-traversal'),
        ('[27] Command Injection', '/command-injection'),
        ('[28] Blind SQL Injection', '/blind-sqli'),
        ('[29] Open Redirect', '/open-redirect'),
        ('[30] HTTP Response Splitting', '/http-response-split'),
        ('[31] File Inclusion Vulnerability', '/file-inclusion'),
        ('[32] XSS-Based Cookie Stealing', '/xss-cookie-theft'),
        ('[33] HTTP Flooding Attack', '/http-flood'),
        ('[34] DDoS Attack Simulation', '/ddos-simulation'),
        ('[35] Email Spoofing', '/email-spoof'),
        ('[36] Buffer Overflow Attack', '/buffer-overflow'),
        ('[37] Phishing Attack', '/phishing'),
        ('[38] SQL Dump Extraction', '/sql-dump'),
        ('[39] Admin Panel Bypass', '/admin-panel-bypass'),
        ('[40] Social Engineering', '/social-engineering'),
        ('[41] DNS Spoofing', '/dns-spoofing'),
        ('[42] Session Fixation', '/session-fixation'),
        ('[43] Header Injection', '/header-injection'),
        ('[44] LDAP Injection', '/ldap-injection'),
        ('[45] XML External Entity Injection (XXE)', '/xxe-injection'),
        ('[46] CRLF Injection', '/crlf-injection'),
        ('[47] URL Redirection Attack', '/url-redirection'),
        ('[48] Firewall Bypass', '/firewall-bypass'),
        ('[49] Brute-Force Hash Cracking', '/hash-cracking'),
        ('[50] CAPTCHA Bypass', '/captcha-bypass'),
        ('[51] Fileless Malware Injection', '/fileless-malware'),
        ('[52] Fake SSL Certificates', '/fake-ssl'),
        ('[53] Web Cache Poisoning', '/web-cache-poisoning'),
        ('[54] Wireless Network Sniffing', '/wifi-sniffing'),
        ('[55] TCP/IP Spoofing', '/tcp-ip-spoofing'),
        ('[56] Heartbleed Exploit', '/heartbleed-exploit'),
        ('[57] SMB Brute Force', '/smb-brute'),
        ('[58] OS Fingerprinting', '/os-fingerprinting'),
        ('[59] Command-Line Injection', '/cmd-injection'),
        ('[60] PHP Reverse Shell', '/php-reverse-shell'),
        ('[61] SMB Relay Attack', '/smb-relay'),
        ('[62] Port Knocking', '/port-knocking'),
        ('[63] DNS Cache Poisoning', '/dns-cache-poisoning'),
        ('[64] IP Spoofing', '/ip-spoofing'),
        ('[65] Cookie Poisoning', '/cookie-poisoning'),
        ('[66] HTTP/2 Attack', '/http2-attack'),
        ('[67] SMB Enumeration', '/smb-enumeration'),
        ('[68] DNS Tunneling', '/dns-tunneling'),
        ('[69] Email Harvesting', '/email-harvesting'),
        ('[70] Rogue DHCP Server Attack', '/rogue-dhcp'),
        ('[71] Cross-Site Script Inclusion (XSSI)', '/xssi'),
        ('[72] DNS Rebinding', '/dns-rebinding'),
        ('[73] Proxy Chaining', '/proxy-chaining'),
        ('[74] Sudo Caching', '/sudo-caching'),
        ('[75] Arbitrary Code Execution', '/arbitrary-code-execution'),
        ('[76] Remote Desktop Protocol (RDP) Attack', '/rdp-attack'),
        ('[77] Privilege Escalation Attack', '/privilege-escalation'),
        ('[78] SSL/TLS Downgrade Attack', '/tls-downgrade'),
        ('[79] Reverse Proxy Attack', '/reverse-proxy-attack'),
        ('[80] Exploit Framework Integration', '/exploit-framework'),
        ('[81] DDoS Attack Tool', '/ddos-attack'),
        ('[82] MITM Attack', '/mitm-attack'),
        ('[83] SSH Bruteforce', '/ssh-bruteforce'),
        ('[84] Web Application Firewall (WAF) Bypass', '/waf-bypass'),
        ('[85] DNS Exfiltration', '/dns-exfiltration'),
        ('[86] SNMP Bruteforce', '/snmp-bruteforce'),
        ('[87] UDP Flood Attack', '/udp-flood'),
        ('[88] XSS Dom-based Attack', '/dom-xss'),
        ('[89] WebDAV Attack', '/webdav-attack'),
        ('[90] Java Deserialization Exploit', '/java-deserialization'),
        ('[91] Distributed Hash Table (DHT) Attack', '/dht-attack'),
        ('[92] SQL Code Execution', '/sql-execution'),
        ('[93] Multi-threaded Brute Force Attack', '/multi-brute-force'),
        ('[94] DNS Amplification Attack', '/dns-amplification'),
        ('[95] DNSSEC Attack', '/dnssec-attack'),
        ('[96] Reverse Shell via Metasploit', '/metasploit-reverse-shell'),
        ('[97] WebSocket Attack', '/websocket-attack'),
        ('[98] Shellshock Exploit', '/shellshock-exploit'),
        ('[99] Fileless Malware Detection', '/fileless-detection'),
        ('[100] Zero-Day Exploit Search', '/zero-day-exploit')
    ]
    
    for tool in tool_list:
        print(f"{magenta}{tool[0]}{reset} - {cyan}{tool[1]}{reset}")

    return tool_list

# 🔹 Main Program Execution
if __name__ == '__main__':
    print(f"{blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
    url = input(f"{magenta}[🌍]{reset} Enter Target URL: ")

    for tool_id, (tool_name, endpoint) in enumerate(tools(), start=1):
        headers = input(f"{magenta}[🛠️]{reset} HTTP Headers for {tool_name} (optional): ")
        headers = {} if not headers else dict(item.strip().split(': ') for item in headers.strip().split(';'))

        cookies = input(f"{magenta}[🍪]{reset} Cookies for {tool_name} (optional): ")
        cookies = {} if not cookies else dict(item.strip().split('=') for item in cookies.strip().split(';'))

        proxy = input(f"{magenta}[🔗]{reset} Proxy (Optional - Format: http://username:password@ip:port): ")
        timeout = int(input(f"{magenta}[⏳]{reset} Timeout (default 5s): ") or 5)

        complete_url = url.rstrip('/') + endpoint
        print(f"{blue}[*]{reset} Sending {tool_name} Request to {complete_url}")
        response = send_http_request(complete_url, method='GET', headers=headers, cookies=cookies, proxy=proxy, timeout=timeout)

        if response:
            print(f"{green}[+]{reset} Response Status: {response.status_code}")
            print(f"{green}[+]{reset} Response: {response.text[:100]}...")  # Displaying only first 100 chars

    print(f"{yellow}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")