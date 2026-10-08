# Passwords in web addresses, and the key formats of the providers AI-built apps use (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.7). Two thin spots in the credential scan (`crates/sv-check/src/
secrets.rs`, `data/secret-rules.json`).

**`secrets.password-in-url`** (high, medium confidence, findings only, citing V13.3.1 and SBD-AC-05). The assignment
rule passes over any value holding `://`, since an address is usually not a credential, so a database address written
with its password (`postgresql://app_owner:…@db.host/app`) was reported by nothing. It is now read in any scheme
(`postgresql`, `mysql`, `mongodb+srv`, `redis`, `amqp`, and the rest), and the password is redacted wherever `sv`
redacts, `.env` files included. Set aside, so the real ones are not buried:

- a reference or a blank to fill in: `${DB_PASSWORD}`, `%(password)s`, `<password>`, `{{…}}`, `xxxxxxxx`, and every
  placeholder the scan already knows;
- a password that spells out the word (`mypassword`, `supersecret`), as examples' do and real ones almost never;
- the stock passwords images and tutorials ship with (`postgres`, `root`, `minioadmin`, and a dozen more), and a
  password that repeats the user name (`appuser:appuser`);
- a `.env` file, where the address belongs, as for the assignment rule.

**Ten provider formats**, each with a prefix of its own, as the published rules write them: SendGrid, Twilio, and
Perplexity from gitleaks; Groq, Replicate, Resend, Supabase (an access token), OpenRouter, Pinecone, and xAI from
TruffleHog (both read 7 October 2026). Each is critical and cites V13.3.1 and SBD-AC-05, as the other vendor rules do.
**Not looked for:** Mailgun, Postmark, Mistral, Cohere, and DeepSeek keys have no prefix of their own, and both tools
match them only beside the provider's name; a pattern for them alone would match ordinary text. A notebook's escaped
JSON, the third thin spot, is not part of this.

Nine guards broken in turn, each caught: no address's password reported; one not redacted; an example password, a stock
password, the user name again, a reference, or a `.env` file reported; Groq's format taken out; and Resend's loosened to
any length. Two witnesses were added when the first run showed the stock list and the user-name check shared one
(`postgres:postgres`). The tests build every key and password from pieces at run time, so no file holds one.
