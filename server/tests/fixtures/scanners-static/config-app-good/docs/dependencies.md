# Keeping the packages up to date

Every package this app depends on is pinned in package-lock.json, and installation never runs package scripts.

| Seriousness | Deadline for applying the update |
| --- | --- |
| Critical | 2 days |
| High | 7 days |
| Everything else | 30 days |

Run `npm audit` and the app's own dependency check after every update, and rebuild so the reports are refreshed.
