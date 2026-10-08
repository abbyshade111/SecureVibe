# V12.3.4 (and V12.3.2): a setting that switches off certificate checking for the whole app

**Status:** done, as its markers read on 8 October 2026

From
`docs/PARTIAL-CHECKS.md` (V12.3.4, level 2, "reads the code, finding only"), which no check speaks to yet.
`NODE_TLS_REJECT_UNAUTHORIZED=0` or `PYTHONHTTPSVERIFY=0` set in a Dockerfile, a compose file, a Kubernetes manifest,
a `.env` file, a workflow, a script, or the code, and the code-level switches that do the same for every
connection (Python's `ssl._create_default_https_context = ssl._create_unverified_context`, Node's
`https.globalAgent.options.rejectUnauthorized = false`, Deno's `--unsafely-ignore-certificate-errors`). One such
line turns off every certificate check the code-level rules look for. Only ever a finding: finding none credits
nothing. The proposal's `CURL_CA_BUNDLE=` is left out unless what it does in today's `requests` can be confirmed,
and its supporting list of trusted internal CAs is not part of this.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
backlog when ready"), in branch `claude/securevibe-e2-cert-checks-off`. A new check that only ever raises findings
changes no requirement's status, so no ADR is proposed.
**Done the same day** (DESIGN, "One setting that switches off certificate checking for the whole app"):
`config.certificate-checks-off`, citing V12.3.2 and V12.3.4. Only ever a finding.
