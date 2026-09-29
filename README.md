# MITRE ATT&CK Analytics

Python tools that analyze Wazuh SIEM alerts from a home lab: rule noise analysis, ATT&CK technique mapping, insider-risk scoring, and a manual ATT&CK coverage-gap tracker.

## Components

| File | What it does |
|------|--------------|
| `siem_analyzer.py` | Reads Wazuh alerts and reports the noisiest rules, an alert-level breakdown, and tuning suggestions for rules that fire 50+ times. |
| `ttp_profiler.py` | Maps alert descriptions to ATT&CK techniques by keyword (for example `sudo` to T1548.003) and groups hits by attack phase. |
| `insider_threat.py` | Builds a per-user risk score from after-hours activity, high-severity events, and event volume, and flags heavy root or system-account usage. |
| `attack_coverage.py` | Prints a table of ATT&CK techniques grouped by tactic, marked covered, partial, or gap, with a coverage score and a list of priority gaps. The statuses are entered by hand as a self-assessment. |

## Requirements

Python 3 and Wazuh. The scripts read `/var/ossec/logs/alerts/alerts.json`, which is root-readable, so run them with `sudo`. `attack_coverage.py` needs no alerts.

## Usage

```bash
sudo python3 siem_analyzer.py
sudo python3 ttp_profiler.py
sudo python3 insider_threat.py
python3 attack_coverage.py
```

## Results

Run against roughly 50 to 60 alerts from a single-user Ubuntu lab VM (counts grow as alerts accumulate):

- **Rule noise:** the noisiest rules were routine PAM session events, sudo, and file-integrity checks. No rule crossed the 50-alert noise threshold.
- **Technique mapping:** the profiler flagged Valid Accounts (T1078), Sudo and Sudo Caching (T1548.003), and Data Manipulation (T1565). All of these came from normal admin activity (logins, sudo, integrity events), which shows how keyword matching produces false positives on benign lab traffic.
- **Insider risk:** the single user scored 0/100. The script flagged system-account usage for review because of frequent sudo.

## Limitations and next steps

- Technique mapping is keyword-based and noisy. A better approach is to use the MITRE fields that Wazuh rules already attach to alerts.
- Coverage statuses in `attack_coverage.py` are self-assessed, not measured against real detection rules.
- Risk and coverage scores are simple heuristics with arbitrary weights and thresholds, not validated models. Scoring people is a sensitive use case, so treat results as prompts for review.
- Reading Wazuh's alerts file requires root, and the scripts only work with a Wazuh install. A sample alerts file would let anyone run them.
- Built and tested on a single-user lab, so results say little about real environments.

## Safety

