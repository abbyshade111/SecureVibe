# A token or a password written into the browser's storage, read from the code (6 October 2026)

Left over from "What the app keeps in the browser after signing in" (BACKLOG): "the pointers from the code". The
running checks (`probe.token-in-browser-storage`, `probe.password-in-browser-storage`) sign in through the app's own
form and read what the page kept. Two code rules now read the page's own scripts for the same thing:

- `ast.token-in-browser-storage` (V10.1.1, medium) and `ast.password-in-browser-storage` (V14.3.3, high), both only
  ever findings. Finding nothing does not show that nothing is kept, since a key held in a variable, or a name that
  does not say what it holds, is not seen.
- **Where:** `localStorage.setItem(…)` and `sessionStorage.setItem(…)`, with or without `window.`, `self.`, or
  `globalThis.`; `storage['…'] = …`; `storage.name = …`; and `document.cookie = 'name=…'`, since a cookie set from
  the page can never be `HttpOnly`.
- **Which names:** for a token, a name holding `token`, `jwt`, or `bearer`, or one that is exactly `auth`,
  `access`, or `refresh`, so `author` is not one. For a password, one holding `password`, `passwd`, `pwd`, or
  `passphrase`.
- **Set aside by name:** a CSRF token, a push-notification token (`fcm`, `apns`, `push`, `device`), and a token's
  expiry. So is a setting about the password field: whether it is shown, its strength, a hint, or "remember".
- JavaScript and TypeScript only. Every other language runs outside the browser and says so (`nothingToFind`). Dart
  says that `dart:html` is not read.

How it is held: 50 witnesses in `the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one`, each form and name in
both languages, with reads, removals, other storage objects, and the set-aside names as controls. Fourteen guards
were undone in turn (each of the four forms in each rule, both lists of names set aside, the exact names, the
`window.` prefix, and `sessionStorage`), and each was caught, one only after a witness for the password rule's
bracket form was added.
