from datetime import datetime

print("== MITRE ATT&CK COVERAGE HEATMAP ==")
print(f"Time: {datetime.now()}\n")

techniques = {
    "Initial Access": {
        "T1566 Phishing":           "PARTIAL",
        "T1190 Public Exploit":     "DETECTED",
        "T1078 Valid Accounts":     "DETECTED",
        "T1133 External Services":  "NOT COVERED"
    },
    "Executiion": {
        "T1059 Command Line":       "DETECTED",
        "T1053 Scheduled Task":     "DETECTED",
        "T1204 User Execution":     "PARTIAL",
        "T1106 Native API":         "NOT COVERED"
    },
    "Persistence": {
       "T1136 Create Account":      "DETECTED",
       "T1053 Cron Job":            "DETECTED",
       "T1546 Event Triggered":     "NOT COVERED",
       "T1037 Boot Script":         "PARTIAL"
    },
    "Privilege Escalation": {
        "T1068 Exploit":            "DETECTED",
        "T1078 Valid Accounts":     "DETECTED",
        "T1548 Abuse Elevation":    "PARTIAL",
        "T1134 Token Manipulation": "NOT COVERED",
    },
    "Defense Evasion": {
        "T1070 Clear logs":         "DETECTED",
        "T1036 Masquerading":       "PARTIAL",
        "T1055 Process Injection":  "NOT COVERED",
        "T1562 Disable Defenses":   "DETECTED",
    },
    "Credential Access": {
        "T1110 Brute Force":        "DETECTED",
        "T1003 Credential Dump":    "PARTIAL",
        "T1552 Unsecured Creds":    "DETECTED",
        "T1558 Kerberoasting":      "NOT COVERED"
    },
    "Discovery": {
        "T1046 Network Scan":       "DETECTED",
        "T1082 System Info":        "DETECTED",
        "T1083 File Discovery":     "PARTIAL",
        "T1018 Remote Systems":     "NOT COVERED",
    },
    "Lateral Movement": {
        "T1021 Remote Services":    "DETECTED",
        "T1550 Pass the Hash":      "NOT COVERED",
        "T1534 Internal Spear":     "NOT COVERED",
        "T1080 Taint Shared":       "NOT COVERED"
    },
    "Exfiltration": {
        "T1041 C2 Channel":         "PARTIAL",
        "T1052 Physical Medium":    "DETECTED",
        "T1567 Web Service":        "NOT COVERED",
        "T1530 Cloud Storage":      "NOT COVERED",
    },
    "Impact": {
        "T1486 Ransomware":         "DETECTED",
        "T1485 Data Destruction":   "DETECTED",
        "T1491 Defacement":         "DETECTED",
        "T1499 Denial of Service":  "PARTIAL"
    }
}

total = covered = partial = uncovered = 0

for tactic, techs in techniques.items():
    print(f"-- {tactic} --")
    for tech, status in techs.items():
        total += 1
        if status == "DETECTED":
            covered += 1
            icon = "[COVERED]"
        elif status == "PARTIAL":
            partial += 1
            icon = "[PARTIAL]"
        else:
            uncovered += 1
            icon = "[GAP]   "
        print(f"  {icon} {tech}")
    print()

coverage = int((covered/total)*100)

print(f"== COVERAGE SUMMARY ==")
print(f"  Total techniques: {total}")
print(f"  Fully covered:    {covered}")
print(f"  Partial:          {partial}")
print(f"  Gaps:             {uncovered}")
print(f"  Coverage score:   {coverage}%")

if coverage >= 70:
    print("  Rating: [STRONG]")
elif coverage >= 50:
    print("  Rating: [MODERATE]")
else:
    print("  Rating: [NEEDS WORK]")

print(f"\n== TOP PRIORITY GAPS ==")
for tactic, techs in techniques.items():
    for tech, status in techs.items():
        if status == "NOT COVERED":
            print(f"  [!] {tech} - {tactic}")
