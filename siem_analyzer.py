import json
from collections import Counter
from datetime import datetime

alerts = []
with open("/var/ossec/logs/alerts/alerts.json") as f:
    for line in f:
        try: alerts.append(json.loads(line))
        except: pass

rule_stats = {}
for a in alerts:
    rule_id = a.get("rule",{}).get("id","")
    rule_desc = a.get("rule",{}).get("description","")
    level = a.get("rule",{}).get("level",0)

    if rule_id not in rule_stats:
        rule_stats[rule_id] = {
            "description": rule_desc,
            "level": level,
            "count": 0
        }
    rule_stats[rule_id]["count"] += 1

print("== SIEM RULE PERFORMANCE ANALYZER ==")
print(f"Generated: {datetime.now()}")
print(f"Total alerts analyzed: {len(alerts)}\n")

print("-- TOP 10 NOISIEST RULES --\n")

sorted_rules = sorted(
    rule_stats.items(),
    key=lambda x: x[1]["count"],
    reverse=True
)

for rule_id, stats in sorted_rules[:10]:
    count = stats["count"]

    if count > 100:
        noise = "[HIGH NOISE - Tune immediately]"
    elif count > 50:
        noise = "[MEDIUM NOISE - Review]"
    elif count > 10:
        noise = "[LOW NOISE - Monitor]"
    else:
        noise = "[NORMAL]"

    print(f"  Rule ID:     {rule_id}")
    print(f"  Description: {stats['description'][:55]}")
    print(f"  Level:       {stats['level']}")
    print(f"  Alert Count: {count}")
    print(f"  Status:      {noise}")

print("-- ALERT LEVEL BREAKDOWN --\n")

levels = Counter()
for a in alerts:
    level = a.get("rule", {}).get("level",0)
    levels[level] += 1

for level in sorted(levels, reverse=True):
    count = levels[level]
    bar = "#" * min(count, 25)
    tag = "[CRITICAL]" if level >= 12 else "[HIGH]" if level >= 8 else "[MEDIUM]" if level >= 4 else "[LOW]"
    print(f"  Level {level:02d} {tag:<12} {bar} {count}")

print("\n-- TUNING RECOMMENDATIONS --\n")

high_noise = [(rid, s) for rid, s in sorted_rules if s["count"] >50]
if high_noise:
    print(f" [!] {len(high_noise)} rules firing 50+ times - candidates for tuning:")
    for rid, s in high_noise[:3]:
        print(f"  Rule {rid}: {s['description'][:50]}")
else:
    print("  [+] No excessively noisy rules detected")

low_level_noise = [(rid, s) for rid, s in sorted_rules
    if s["count"] > 20 and s["level"] < 5]
if low_level_noise:
    print(f"\n  [!] {len(low_level_noise)} low-level rules are very noisy:")
    print(f"      Consider suppressing or increasing threshold")

print("\n-- DETECTION COVERAGE SCORE --\n")

critical_rules = sum(1 for r in rule_stats.values() if r["level"] >= 12)
high_rules = sum(1 for r in rule_stats.values() if 8 <= r["level"] < 12)
total_rules = len(rule_stats)

print(f"  Total unique rules triggered: {total_rules}")
print(f"  Critical level rules:         {critical_rules}")
print(f"  High level rules:             {high_rules}")

coverage = min(100, (total_rules * 2))
print(f" Detection coverage score:      {coverage}/100")

print("\n======================================")
print("  Save this output for your IR report")
print("=====================================")
