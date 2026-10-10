# A prompt that reads StackVet's report with you

StackVet's report is honest, and it is long. It leads with what was not examined, it never says a requirement passed,
and it names what only you can check. For someone who is not a programmer that can be a lot to take in at once.

This prompt asks your AI coding tool to read the report with you in a fixed order: first what was not checked and
what that means for you, then at most three things to do first, then your questions. It tells the tool never to say
the app is secure, safe, compliant, or that it passed, because the report does not say that and cannot, and never to
soften what the report says. It is an instruction, not evidence: the report is the evidence, and the prompt asks the
tool to explain it, not to add to it.

**Tried so far:** not yet in any AI coding tool. A test holds the prompt to the report StackVet writes: every
section it names is one `compliance.md` really has (`crates/sv-cli/tests/report_prompt.rs`). Until someone has tried
it, read the report's own "The short version" and "What was not examined" yourself as well.

**Where to find it.** After StackVet has checked the app, paste the prompt below into your AI coding tool. If the
tool is connected to StackVet, StackVet also offers it as a prompt called `read-my-report` (Claude Code lists a
connected server's prompts among its `/` commands; whether this one shows up there has not been checked yet), and
`sv prompts report` prints it.

<!-- report-prompt:start -->
> Please read StackVet's report on this app with me. It is in the `stackvet-report` folder (or `securevibe-report`,
> from an older version): start with `compliance.md`, and use `security.md` for the details of anything it found. If
> there is no report there, tell me so, and that the app needs checking with StackVet first; do not guess what a
> report would say. I am not a programmer, so explain each technical word the first time you use it. Go in this
> order:
>
> 1. What was not checked, first. Read "What was not examined", the line that starts "Not run this time" if there
> is one, and the requirements counted as not verified or not yet placed. Tell me in plain words what each means
> for me: what could be wrong with the app that this report would not show. Do not skip this, and do not make it
> sound minor.
> 2. At most three things to do first. Take them from "What to do next" and the worst findings in "The short
> version", in the report's order. For each, tell me what it is, why it matters to the people who will use the
> app, and what to do about it. If the report gives fewer than three, say so; do not add more.
> 3. Then ask me what I would like to know more about.
>
> Never tell me the app is secure, safe, compliant, or that it passed: the report does not say that, and it cannot.
> A requirement marked checked means a check looked and found nothing wrong over the coverage named beside it, not
> that the requirement is met; say it that way. Do not soften what the report says. Give numbers exactly as the
> report does. If you notice something yourself that the report does not say, tell me it is your own observation,
> not StackVet's.
<!-- report-prompt:end -->

The words used here are explained in [the glossary](../GLOSSARY.md).
