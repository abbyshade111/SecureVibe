# Talking to other services

This app can only call other web services through one function, and only to hosts that are explicitly allowed.

## Currently allowed

*(none — the allow-list is empty, so the app cannot call out to anything)*

## Rules that always apply

- Only https:// and http:// addresses; credentials embedded in the address are refused.
- Redirects are never followed automatically, every call times out, and certificate checks are never turned off.
