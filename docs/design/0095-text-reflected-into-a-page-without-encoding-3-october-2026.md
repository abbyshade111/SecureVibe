# Text reflected into a page without encoding (3 October 2026)

The stranger probes now send one value, `svEcho4b7e<"'e7b4ohcEvs`, in three addresses: the health path and the root
page with it as `q` (the parameter a search reads), and a page that does not exist with it in the path, which an
error page often repeats. The `<`, `"`, and `'` are percent-encoded, as a browser sends them. What came back between
the two ends of the value is read for each answer:

- **In a page (an HTML content type), a `<` as it is** is `probe.reflected-unencoded` (V1.2.1, CWE-79, high): the
  browser reads it as the start of a tag, which is reflected cross-site scripting. Only the `<` decides. A quote as it
  is is harmless in text and harmful in an attribute, and which one it landed in is not read, so a page that encodes
  the `<` and not the quotes is not judged either way.
- **In JSON, a `"` with no backslash before it** is `probe.reflected-json-unescaped` (V1.2.3, medium): it ends the
  string it was written into.
- **Encoded, percent-encoded, taken out, or not repeated at all** is no finding, and **never credit**. V1.2.1 asks for
  the right encoding everywhere the app writes out what it was sent; one value on three pages does not show that, and
  a single unescaped template elsewhere breaks it. This follows the same reasoning as session securevibe-e9's
  withdrawal of six proposed credits the same day. The backlog item proposed credit for an encoded page; it is not
  given. `tools/coverage.py` lists both rules in `RUST_FINDINGS_ONLY`.
- **An answer of any other type, or with none said, is not judged.**

**The runner keeps the text around the value.** It keeps only the first 4,000 characters of an answer, and a page
often repeats a search term further down than that. When the value comes back past the cut, `parse_response` in
`sv-run` also keeps 200 characters on each side of it, at most five times. The value is one only `sv` sends, so no
other answer keeps more than it did.

Tried on 3 October 2026 with `sv report --run` against two scratch apps, built with Python's standard library only:
- The app that writes the search term and the path into its pages unencoded was found on the root page and the
  missing page.
- The same app with `html.escape` was not found, and V1.2.1 stayed not verified.
- Both answered JSON on the health path through `json.dumps`, and neither was found for it.
- An app whose echo sat 7,800 characters down the page was found.
