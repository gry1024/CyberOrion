
import re, requests

s = requests.Session()

# Step 1: GET login page to grab CSRF token
r = s.get("http://localhost:28080/login.php")
token = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
print(f"[*] Got CSRF token: {token}")

# Step 2: Login with default creds
data = {
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}
r = s.post("http://localhost:28080/login.php", data=data, allow_redirects=True)
print(f"[*] After login, URL: {r.url}")
print(f"[*] Page title match: {'Setup' in r.text}")

# Step 3: Check if setup page has a CSRF token and a Create button
setup_token_match = re.search(r"name='user_token' value='([^']+)'", r.text)
if setup_token_match:
    setup_token = setup_token_match.group(1)
    print(f"[*] Setup page token: {setup_token}")
    
    # Click "Create / Reset Database"
    setup_data = {
        "create_db": "Create / Reset Database",
        "user_token": setup_token
    }
    r2 = s.post("http://localhost:28080/setup.php", data=setup_data, allow_redirects=True)
    print(f"[*] Setup response URL: {r2.url}")
    if "success" in r2.text.lower() or "created" in r2.text.lower():
        print("[+] Database setup successful!")
    else:
        print("[*] Setup page response (first 300 chars):")
        print(r2.text[:300])
else:
    print("[-] No setup token found, checking page...")
    print(r.text[:500])

# Step 4: Now try logging in again
r3 = s.get("http://localhost:28080/login.php")
token2 = re.search(r"name='user_token' value='([^']+)'", r3.text)
if token2:
    token2 = token2.group(1)
    data2 = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token2
    }
    r4 = s.post("http://localhost:28080/login.php", data=data2, allow_redirects=True)
    print(f"\n[*] Second login URL: {r4.url}")
    if "Welcome" in r4.text or "index.php" in r4.url:
        print("[+] SUCCESS: Logged into DVWA as admin!")
        print(f"[*] Cookies: {dict(s.cookies)}")
    else:
        print(f"[-] Still not logged in. Title: {re.search(r'<title>([^<]+)', r4.text).group(1) if re.search(r'<title>([^<]+)', r4.text) else 'unknown'}")

