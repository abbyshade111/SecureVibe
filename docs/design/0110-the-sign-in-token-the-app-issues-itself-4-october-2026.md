# The sign-in token the app issues itself (4 October 2026)

Many apps an AI coding tool writes sign a person in by handing them a JSON Web Token (a JWT): three parts separated
by dots, the first two being JSON anybody can read (which signing method was used, and who the person is and until
when), and the third a signature over them made with the app's key. The token is only as good as the app's checks on
it, and three of those checks are easy to leave out: the signature itself, refusing a token that says it needs no
signature (`alg: none`), and the expiry time written in it. The owner decided on 4 October 2026 that `sv` should ask
all three, with the real token as the control, and not the two forms that point the app at a key the probe controls
(`jku`, `kid`), which would need a key server inside the fence.

How it is asked (`crates/sv-check/src/signed_in/tokens.rs`). When the test user's sign-in hands back a JWT, as the
token in the JSON answer or as a cookie's value, every request below carries only that token, exactly the way it came,
to the private page the sign-in was shown to open.

- **The control.** The real token alone must open the page. When it does not, the app needs more than the token (a
  second cookie, say), a refusal of a changed one would show nothing, and the checks are not assessed, saying so.
- **Signature (`probe.app-token-signature-not-checked`, V9.1.1).** A field (`sv_probe`) is added to what the token
  says and the signature is kept. Only an app that checks the signature notices. Opened is a critical finding;
  refused is credit.
- **`alg: none` (`probe.app-token-alg-none`, V9.1.2).** What the token says is kept, its header is marked as needing
  no signature, and none is sent. Opened is a critical finding; refused is credit.
- **Expiry (`probe.app-token-expired-accepted`, V9.2.1).** An expired token cannot be made without the app's key,
  because the expiry is inside what is signed, so the only honest way to ask is to wait for a real one to run out.
  With a sign-in of its own, late in the run (after everything that needed A's first session, before the password
  changes), the token is shown to open the page and then sent again 65 seconds after its expiry. The extra minute is
  deliberate: many token libraries accept a token up to a minute late to allow for clocks that disagree, which is
  common practice and not a fault, and asking sooner would accuse every app that allows it. A refusal is credited
  only when a sign-in begun afterwards still opens the page, so an app that stopped answering is not credited.

**The limit on expiry.** A run waits only for a token due to run out within a minute (so at most two minutes and five
seconds), or within 90 minutes with `sv run --slow`, the same cap the session timeouts use. A token that lasts longer,
which is most of them (15 minutes and an hour are common), leaves V9.2.1 not assessed, saying how long the token lasts
and that `--slow` waits longer. A token with no expiry at all is not assessed either, saying that unless the app keeps
a list of the tokens it issued, one copied once works for good. That is said, not cited: no requirement the check
speaks to asks for an expiry to be there.

What these do not do: forge a token the app would accept (that needs its key, which `sv` never has), try the other
spellings of `none` (`None`, `NONE`), or look at tokens other than the one the sign-in hands back. Each changed-token
request is in `RESTS_ON_A_REFUSAL`, so a crash never turns into credit, and the crash sweep has a scenario with the
fake app's signature and expiry checks both switched off.

The fake app hands out real HS256 tokens when `jwt_lifetime` is set (with an id of their own, so two sign-ins in the
same second do not get the same token, which first made a new sign-in's token match one already signed out), with a
switch for each fault and a `jwt_leeway` for the allowance that is not one. Twenty-four guards were broken in turn,
the three rows of `RESTS_ON_A_REFUSAL` among them, each caught by the crash sweep. Twenty-three were caught at first;
the one that was not, carrying a cookie's token in the `Authorization` header
instead, went unnoticed because the fake app reads either, and the test now holds which header every token request
carries.
