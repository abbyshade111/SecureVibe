# What people may type

Every form and every API call is checked against a strict rule before anything is stored: unknown fields are
refused, text has a maximum length, numbers have a range, and dates must be real dates.

| Field | Rule |
| --- | --- |
| Text | 1 to 200 characters, trimmed |
| Long text | Up to 4000 characters |
| Numbers | Whole numbers within the documented range |

Per-person limits (how many records one account may create, and how often) are listed in docs/SECURITY.md.
Anything that does not fit a rule is refused with a message that says which field was wrong, and nothing is stored.
