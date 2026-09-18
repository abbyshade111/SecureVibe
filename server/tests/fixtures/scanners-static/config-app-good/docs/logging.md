# What is logged

Two things are written for every security-relevant action: a structured log line, and a row in a tamper-evident
security event table.

| What | Detail |
| --- | --- |
| Application log | JSON lines at DATA_DIR/app.log |
| Security event log | An append-only table in the database, kept for at least 400 days |

Passwords, one-time codes and session ids are never written to either of them.
