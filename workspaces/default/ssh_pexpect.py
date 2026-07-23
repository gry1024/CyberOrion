import subprocess
import sys

# First check if expect is available
result = subprocess.run(['which', 'expect'], capture_output=True, text=True)
if result.returncode == 0:
    print("expect found at:", result.stdout.strip())
else:
    print("expect not found")

# Try with pexpect
try:
    import pexpect
    print("pexpect is available!")
    
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=no -p 22222 ctf@localhost "cat /home/ctf/flag.txt"', timeout=15)
    i = child.expect(['[Pp]assword', pexpect.EOF, pexpect.TIMEOUT])
    if i == 0:
        child.sendline('ctf')
        child.expect(pexpect.EOF)
        print(child.before.decode())
    elif i == 1:
        print("Connection closed before password prompt")
        print(child.before.decode())
    else:
        print("Timeout")
        print(child.before.decode() if child.before else "nothing")
except ImportError:
    print("pexpect not available")
except Exception as e:
    print(f"Error: {e}")

