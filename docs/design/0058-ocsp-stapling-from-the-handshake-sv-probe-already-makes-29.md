# OCSP stapling, from the handshake `sv probe` already makes (29 September 2026)

V12.1.4 asks that "proper certification revocation, such as Online Certificate Status Protocol (OCSP)
Stapling, is enabled and configured". It was left out of `sv probe` on 26 September because it could
not be observed from the machine that built the probe: its only way out intercepted TLS, so every
handshake it saw was the proxy's. From the owner's Mac on 29 September it could be: DigiCert's and
Microsoft's sites stapled a good status, and the certificate seen was DigiCert's own, not a proxy's.

**What curl can say, measured.** curl 8.12.1 (OpenSSL 3.0.17, the one macOS ships) answers both
halves. `--write-out '%{certs}'` prints the certificate chain with its extensions as text, the site's
certificate first, and a certificate that names a responder has a line `Authority Information
Access:OCSP - URI:http://ocsp.digicert.com`. `--cert-status` makes the handshake require a stapled
status: success when one came back good, exit 91 with "No OCSP response received" when none did. On
the day: www.digicert.com and www.microsoft.com staple; github.com's certificate names Sectigo's
responder and staples nothing; letsencrypt.org's names no responder at all, only where its issuer is
published, which is so for every Let's Encrypt certificate since 2025.

**The check.** The first HTTPS request, the one whose handshake is already the V12.2.2 check, also
asks curl for the certificate's details, marked off after the headers, so whether the certificate
names a responder costs no request. Then, only for a certificate this machine trusts:
- names a responder: one HEAD with `--cert-status`. Stapled is credited, naming the responder; none
  stapled is `probe.ocsp-not-stapled`, low, only ever about a certificate that names one;
- names none: not assessed, saying so, since there is no status to staple and that says nothing
  about how revocation is handled instead (short-lived certificates, CRLs);
- no details reported (a curl without `%{certs}`): not assessed, saying curl did not report them.
Exit 91 with any other message (a status that came back and said revoked, or expired) is not "none
stapled": it is passed on, in curl's own words, as the reason nothing was concluded. Any other failure
is not assessed with curl's message.

**Still at most four requests.** Asking the owner, the stapling request was first counted as a fifth,
and the owner agreed to raise the cap to five. Counting what a run really makes showed that wrong: the
unverified retry happens only when the certificate fails, and the stapling question only when it
passed and names a responder, never both, so a run makes at most three (HTTPS, one of those two,
plain HTTP). The cap stays four, `CLAUDE.md`'s promise stands as written, and a test holds a run with
the stapling question at three requests, every one of them reported to the owner.

**Broken on purpose eight ways**, each restored from the bytes read before it: asking with no
responder; crediting a site that staples nothing; reading any exit 91 as none stapled; reading the
responder from anywhere in the chain (Let's Encrypt's issuer names one; the site's certificate does
not); asking after an untrusted certificate; reading no details as no responder; not reporting the
stapling request; and not asking curl for the certificate's details. Each is caught by two tests.
The first pass found two faults in the tests themselves: the break for asking with no responder did
not compile, so it had shown nothing, and asking after an untrusted certificate was caught by nothing,
because the test's fake failed the retry too and the run ended before the question. Both were fixed,
and an end-to-end test from curl's own output was added as the second witness for six of them.
