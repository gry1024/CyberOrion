
import requests
import re

BASE = "http://127.0.0.1:28080"
s = requests.Session()

# Check login page
r = s.get(f"{BASE}/login.php")
print(f"[+] Login page status: {r.status_code}")
print(f"[+] Cookies after login page: {dict(s.cookies)}")

# Get CSRF token
token = re.search(r"user_token' value='([a-f0-9]+)'", r.text)
if token:
    token = token.group(1)
    print(f"[+] Token: {token}")
else:
    print("[!] No token found")
    print(r.text[:500])

# Login with follow redirect to see what happens
r = s.post(f"{BASE}/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)
print(f"\n[+] Post-login URL: {r.url}")
print(f"[+] Post-login status: {r.status_code}")
print(f"[+] Cookies: {dict(s.cookies)}")

# Check if we can access index.php directly
r2 = s.get(f"{BASE}/index.php", allow_redirects=False)
print(f"\n[+] index.php direct: {r2.status_code} -> {r2.headers.get('Location','')}")

# Check setup.php content
r3 = s.get(f"{BASE}/setup.php")
# look for any error or success messages
messages = re.findall(r'<div[^>]*class="[^"]*"[^>]*>(.*?)</div>', r3.text, re.DOTALL)
print(f"\n[+] Setup page messages: {len(messages)}")
for m in messages[:5]:
    clean = re.sub(r'<[^>]+>', '', m).strip()
    if clean:
        print(f"    {clean[:200]}")

# Check if there's a database config issue
r4 = s.get(f"{BASE}/config/config.inc.php", allow_redirects=False)
print(f"\n[+] Config page: {r4.status_code}")
if r4.status_code == 200:
    print(r4.text[:300])

