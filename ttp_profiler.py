import json
from collections import Counter
from datetime import datetime

alerts = []
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        try: alerts.append(json.loads(line))
        except: pass

print("== ATTACKER TTP PROFILER ==")
print("MITRE ATT&CK Framework Analysis")
print(f"Time: {datetime.now()}\n")

ttp_map = {
    "brute":   ("T1110", "Brute Force", "Credential Access"),
    "ssh":     ("T1021", "Remote Services", "Lateral Movement"),
    "sudo":    ("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation"),
    "login":   ("T1078", "Valid Accounts", "Defense Evasion"),
    "scan":    ("T1046", "Network Service Discovery", "Discovery"),
    "file":    ("T1565", "Data Manipulation", "Impact"),
    "cron":    ("T1053", "Scheduled Task", "Persistence")
}

ttps = Counter()
for a in alerts:
    desc = a.get("rule",{}).get("description","").lower()
    for keyword, (tid, name, tactic) in ttp_map.items():
        if keyword in desc:
            ttps[tid] += 1

print("-- DETECTED TECHNIQUES --\n")
if ttps:
    for tid, count in ttps.most_common():
        for keyword, (t, name, tactic) in ttp_map.items():
            if t == tid:
              print(f"  {tid} | {name:<30} | {tactic}")
              print(f"  Count: {count}\n")
else:
    print("  No techniques mapped yet\n")

print("-- ATTACK PHASE BREAKDOWN --\n")
phases = {
    "Reconnaissance":      ["T1046","T1595"],
    "Initial Access":      ["T1078","T1566"],
    "Execution":           ["T1059","T1053"],
    "Persistence":         ["T1053","T1136"],
    "Privilege Escalation":["T1548.003","T1078"],
    "Lateral Movement":    ["T1021","T1550"],
    "Impact":              ["T1486","T1565"]
}

for phase, techniques in phases.items():
    hits = sum(ttps.get(t,0) for t in techniques)
    tag = "[DETECTED]" if hits > 0 else "[CLEAR]"
    print(f"  {tag} {phase:<25} {hits} events")

print(f"\n-- SUMMARY --\n")
print(f"  Total alerts:      {len(alerts)}")
print(f"  Techniques seen:   {len(ttps)}")
print(f"  Phases detected:   {sum(1 for p,t in phases.items() if sum(ttps.get(x,0) for x in t) > 0)}")
