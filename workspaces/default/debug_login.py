
import requests
import re

s = requests.Session()

# Step 1: Get login page
login_page = s.get('http://localhost:28080/login.php')
print(f"[1] Login page status: {login_page.status_code}")
print(f"[1] Cookies after loading login page: {dict(s.cookies)}")

token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", login_page.text)
if token_match:
    token = token_match.group(1)
    print(f"[1] CSRF token: {token}")

# Step 2: Login
login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': token
}
# allow_redirects=True this time to follow the 302
login_resp = s.post('http://localhost:28080/login.php', data=login_data, allow_redirects=True)
print(f"\n[2] Login POST status: {login_resp.status_code}")
print(f"[2] Final URL: {login_resp.url}")
print(f"[2] Cookies after login: {dict(s.cookies)}")
print(f"[2] Response length: {len(login_resp.text)}")

# Check if we're logged in
if 'Welcome' in login_resp.text or 'Logged in' in login_resp.text:
    print("[2] ✅ LOGIN SUCCESSFUL!")
elif 'Login failed' in login_resp.text or 'CSRF token is incorrect' in login_resp.text:
    print("[2] ❌ LOGIN FAILED!")
    # Find the error message
    msg_match = re.search(r'<div class="warning">(.*?)</div>', login_resp.text)
    if msg_match:
        print(f"[2] Error: {msg_match.group(1)}")
    msg_match2 = re.search(r'<div class="message">(.*?)</div>', login_resp.text)
    if msg_match2:
        print(f"[2] Message: {msg_match2.group(1)}")
else:
    # Check for other indicators
    if 'user_token' in login_resp.text:
        print("[2] Still on login page (has user_token)")
        # Try to find any error
        errors = re.findall(r'class="(warning|message|error)"[^>]*>(.*?)</div>', login_resp.text, re.DOTALL)
        for cls, msg in errors:
            print(f"[2] Error ({cls}): {msg.strip()}")
    elif 'index.php' in login_resp.url or 'setup.php' in login_resp.url:
        print("[2] ✅ Redirected to main page - likely logged in!")

# Step 3: Try accessing a page directly
print(f"\n[3] Testing session validity...")
index_resp = s.get('http://localhost:28080/index.php')
print(f"[3] Index status: {index_resp.status_code}")
print(f"[3] Index URL: {index_resp.url}")
if 'Welcome' in index_resp.text or 'dashboard' in index_resp.text.lower():
    print("[3] ✅ SESSION VALID - can access index.php")
else:
    print("[3] ❌ SESSION INVALID - redirected or no access")
    
# Step 4: Try to set security level to low via the security page
print(f"\n[4] Attempting to change security level via DVWA security page...")
sec_page = s.get('http://localhost:28080/security.php')
print(f"[4] Security page status: {sec_page.status_code}")
print(f"[4] Security page URL: {sec_page.url}")

# Check if we can access it
if 'Security' in sec_page.text and 'Low' in sec_page.text:
    print("[4] ✅ Can access security page!")
    # Get CSRF token from security page
    sec_token = re.search(r"user_token.*?value='([a-f0-9]+)'", sec_page.text)
    if sec_token:
        sec_token = sec_token.group(1)
        print(f"[4] Security page CSRF token: {sec_token}")
        # Try to set security to low
        sec_data = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': sec_token
        }
        sec_resp = s.post('http://localhost:28080/security.php', data=sec_data, allow_redirects=True)
        print(f"[4] Set security response: {sec_resp.status_code}")
        print(f"[4] Cookies after setting: {dict(s.cookies)}")
else:
    print("[4] ❌ Cannot access security page")
    print(f"[4] Content preview: {sec_page.text[:300]}")

