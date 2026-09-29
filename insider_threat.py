import json
from collections import defaultdict
from datetime import datetime

alerts = []
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        try: alerts.append(json.loads(line))
        except: pass

print("== INSIDER THREAT DETECTOR ==")
print(f"Time: {datetime.now()}\n")

user_activity = defaultdict(list)
for a in alerts:
    user = a.get("data",{}).get("dstuser","")
    hour = a.get("timestamp","")[11:13]
    desc = a.get("rule",{}).get("description","")
    level = a.get("rule",{}).get("level",0)
    if user and user not in ["root","system",""]:
        user_activity[user].append({
            "hour": hour,
            "desc": desc,
            "level": level
        })

print("-- USER BEHAVIOR ANALYSIS --\n")

if user_activity:
    for user, activities in user_activity.items():
        risk_score = 0
        flags = []

        after_hours = [a for a in activities
            if a["hour"] in ["00","01","02","03","22","23"]]
        if after_hours:
            risk_score += 30
            flags.append("After hours activity detected")

        high_alerts = [a for a in activities if a["level"] >= 8]
        if high_alerts:
            risk_score += 40
            flags.append(f"{len(high_alerts)} high severity events")

        if len(activities) > 20:
            risk_score += 20
            flags.append("Unusually high activity volume")

        tag = "[HIGH RISK]" if risk_score >= 50 else "[MONITOR]" if risk_score >= 20 else "[NORMAL]"
        print(f"  {tag} User: {user}")
        print(f"         Risk Score:  {risk_score}/100")
        print(f"         Total Events:{len(activities)}")
        if flags:
            for flag in flags:
                print(f"        [!] {flag}")
        print()
else:
    print("  No user activity found in alerts")
    print("  System activity is being monitored\n")

print("-- SYSTEM ACCOUNT ACTIVITY --\n")
system_activity = [a for a in alerts if
    a.get("data",{}).get("dstuser","") in ["root","system"]]

print(f"  Root/System events: {len(system_activity)}")
if len(system_activity) > 10:
    print(f"  [REVIEW] High system account usage")
else:
    print(f"  [NORMAL] System account usage normal")

print(f"""
-- SUMMARY --
  Total alerts analyzed: {len(alerts)}
  User monitored:        {len(user_activity)}
  High risk users:       {sum(1 for u,a in user_activity.items() if len(a) > 20)}

""")
