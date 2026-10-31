# Checks performed

- The supplied logs load without crashing: 4,948 accepted and 32 skipped rows.
- Five failures exactly ten minutes apart trigger a brute-force alert.
- Five failures spread across eleven minutes do not trigger the same alert.
- A staff login at 22:00 is flagged; a staff login at 05:00 is allowed.
- Empty and missing log files return an empty list with an explanation.
