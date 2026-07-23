
import subprocess, re

# Step 1: GET the login page to grab the user_token
result = subprocess.run(
    ['curl', '-s', '-c', '/tmp/dvwa_cj', '-b', '/tmp/dvwa_cj', 
     'http://localhost:28080/login.php'],
    capture_output=True, text=True
)
html = result.stdout

# Extract the CSRF token
token_match = re.search(r"name='user_token'\s+value='([a-f0-9]+)'", html)
if token_match:
    token = token_match.group(1)
    print(f"[+] Extracted user_token: {token}")
else:
    print("[-] Could not find user_token!")
    print(html[:500])
    exit(1)

# Step 2: POST login with the token
result2 = subprocess.run(
    ['curl', '-s', '-c', '/tmp/dvwa_cj', '-b', '/tmp/dvwa_cj', '-L',
     '-d', f'username=admin&password=password&Login=Login&user_token={token}',
     'http://localhost:28080/login.php'],
    capture_output=True, text=True
)

# Check if login succeeded
if 'Welcome' in result2.stdout or 'index.php' in result2.stdout or 'Logged' in result2.stdout:
    print("[+] Login SUCCESSFUL!")
elif 'CSRF' in result2.stdout or 'Login' in result2.stdout:
    print("[-] Login failed - CSRF error or redirect back to login")
    # Show snippet
    print(result2.stdout[:500])
else:
    print("[?] Unclear result, checking...")
    print(result2.stdout[:800])

# Show cookies
import os
if os.path.exists('/tmp/dvwa_cj'):
    with open('/tmp/dvwa_cj') as f:
        print(f"\n=== COOKIES ===\n{f.read()}")

