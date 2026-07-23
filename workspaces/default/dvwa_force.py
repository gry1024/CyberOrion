
import requests
import re

BASE = "http://127.0.0.1:28080"
s = requests.Session()

# Get initial session
r = s.get(f"{BASE}/login.php")
token = re.search(r"user_token' value='([a-f0-9]+)'", r.text).group(1)

# Login
s.post(f"{BASE}/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
})

# Force security cookie to "low"
s.cookies.set("security", "low", domain="localhost")
print(f"[+] Cookies: {dict(s.cookies)}")

# Try to reset/create database 
r = s.get(f"{BASE}/setup.php")
print(f"[+] Setup page: {r.status_code}")

# Submit the create DB form
r = s.post(f"{BASE}/setup.php", data={"create_db": "Create / Reset Database"}, allow_redirects=True)
print(f"[+] After DB reset: {r.status_code}, URL: {r.url}")

# Look for success/error in response
success = re.findall(r'<span[^>]*style="[^"]*color:\s*green[^"]*"[^>]*>(.*?)</span>', r.text, re.DOTALL)
errors = re.findall(r'<span[^>]*style="[^"]*color:\s*red[^"]*"[^>]*>(.*?)</span>', r.text, re.DOTALL)
for s_msg in success:
    print(f"  [OK] {re.sub(r'<[^>]+>','',s_msg).strip()[:200]}")
for e_msg in errors:
    print(f"  [ERR] {re.sub(r'<[^>]+>','',e_msg).strip()[:200]}")

# Also print any relevant text about database
db_info = re.findall(r'(Database|MySQL|Error|Warning)[^<]{0,200}', r.text)
for d in db_info[:10]:
    print(f"  [info] {d.strip()[:200]}")

# Try to access SQLi page with security=low cookie
r = s.get(f"{BASE}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"})
print(f"\n[+] SQLi page status: {r.status_code}")
print(f"[+] SQLi page length: {len(r.text)}")

# Check if there's actual content or redirect
if "First name" in r.text:
    print("[+] Got SQLi results!")
    rows = re.findall(r'First name:\s*(\S+)<br\s*/?>\s*Surname:\s*(\S+)', r.text)
    for row in rows:
        print(f"    {row}")
else:
    # Print relevant snippet
    snippet = r.text[max(0,r.text.find('<div class="body_padded">')-50):r.text.find('<div class="body_padded">')+500] if 'body_padded' in r.text else r.text[:500]
    print(f"  [snippet] {snippet[:400]}")

