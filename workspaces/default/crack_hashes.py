
import hashlib

# Known DVWA default passwords
passwords = ['password', 'abc123', 'letmein', 'charley', 'password123', 'admin', 'pass', '123456']
hashes = {
    'admin': '5f4dcc3b5aa765d61d8327deb882cf99',
    'gordonb': 'e99a18c428cb38d5f260853678922e03',
    '1337': '8d3533d75ae2c3966d7e0d4fcc69216b',
    'pablo': '0d107d09f5bbe40cade3de5c71e9e9b7',
}

print("CRACKING DVWA PASSWORD HASHES")
print("=" * 50)

for user, target_hash in hashes.items():
    for pw in passwords:
        if hashlib.md5(pw.encode()).hexdigest() == target_hash:
            print(f"  [+] {user}:{pw} (hash: {target_hash[:16]}...)")
            break
    else:
        print(f"  [-] {user}: hash not cracked (hash: {target_hash[:16]}...)")

print("\n[+] 4/4 passwords cracked using DVWA default password list")
print("[+] Blue Team should have changed default passwords!")

