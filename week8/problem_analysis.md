# SentinelGH: Problem Analysis (Week 8)

**Client:** Nkabom Savings & Loans | **Course:** WIT 102, Introduction to Python Programming | **Team:** ________

## 1. The problem
Nkabom Savings & Loans has branches in Accra, Kumasi and Takoradi and about 18,000 customers who use a web portal and USSD. Staff log in to an internal system to approve transactions. Over the last three months:

- Customers have been locked out of accounts they did not try to open, which points to **brute-force** and **password-spraying** attacks.
- Staff accounts have been accessed **late at night from IP addresses outside Ghana**, which suggests stolen staff credentials.
- An audit found **weak staff passwords** (e.g. `password123`, `Nkabom2025`).
- The **Bank of Ghana cyber and information security directive** requires the company to show that it monitors access and reports incidents.

The company has login logs (CSV) but no security tool and no analyst to read them. The logs also contain errors (blank cells, bad dates, duplicate rows), so any tool must handle bad data without crashing.

## 2. Who is affected
| Stakeholder | How they are affected |
|---|---|
| Customers | Locked out of their accounts; risk of losing money if an attacker gets in |
| Staff | Their accounts can be used to approve fraudulent transactions |
| IT officer | Has to check thousands of log lines by hand |
| IT manager / management | Needs evidence for the board and the regulator |
| Bank of Ghana (regulator) | Expects access monitoring and incident reporting |

## 3. What SentinelGH will do
1. **Read** `auth_log.csv` safely, skipping bad or duplicate rows and recording why each was skipped.
2. **Detect** brute force (5 or more failures on one account in 10 minutes), password spraying (one IP failing on 5 or more accounts), staff logins between 10pm and 5am, and logins from foreign IP addresses.
3. **Count** failed logins per user and per IP address to show who is attacked and from where.
4. **Report** alerts, ranked by severity, to `alerts_week8.txt` from a simple menu the IT officer can run every morning.
5. *(Later weeks)* Audit staff passwords, model the data as classes, and add charts and a daily incident report.

## 4. Pseudocode: brute-force detection rule
```
FUNCTION find_brute_force(logs, limit = 5)
    failures_by_user ← empty dictionary
    FOR each record IN logs
        IF record.status is FAIL or LOCKED THEN
            add record to failures_by_user[record.username]

    alerts ← empty list
    FOR each user, failures IN failures_by_user        // failures are in time order
        start ← 0
        WHILE start < length(failures)
            end ← start
            WHILE next failure exists AND next.time − failures[start].time ≤ 10 minutes
                end ← end + 1
            count ← end − start + 1
            IF count ≥ limit THEN
                add alert(BRUTE_FORCE, HIGH, user, failures[start].time, count, IPs)
                start ← end + 1          // report each attack only once
            ELSE
                start ← start + 1
    RETURN alerts
```
