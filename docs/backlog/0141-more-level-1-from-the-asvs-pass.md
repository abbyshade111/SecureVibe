# More Level 1 from the ASVS pass

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 by session securevibe-e8. From
the 41 Level 1 requirements no check reached: signed-in questions for V6.2.8 (a password checked
exactly as typed, not cut short or case-folded), V6.2.6 (password fields masked), V6.2.7 (paste not
blocked), and V3.5.3 (sign-out and creating a record refused as a plain page visit); semgrep's rules
for text written into a page as HTML against V3.2.2 and C#'s turned-off token expiry against V9.2.1,
as findings only; then a `change-password` entry for V6.2.2 and V6.2.3. All done, with V6.2.9 beside
V6.2.8 (see DESIGN, "Level 1 again"); creating a record by a plain page visit was left out, because
telling whether a GET made one needs a page that lists them.
