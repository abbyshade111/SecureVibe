//! "Read my report with me" (backlog 0217 part 5): a prompt that has the person's AI coding tool
//! explain StackVet's report to someone who is not a programmer, starting with what was not
//! checked, then at most three things to do first, and never saying the app is secure.
//!
//! `sv prompts report` prints it, the MCP server offers it beside the design-time prompts, and
//! `docs/prompts/report.md` shows it to a person; a test holds all three to these words and holds
//! every section the prompt names to the report `sv` writes.

/// The name the MCP server offers it under.
pub const ID: &str = "read-my-report";

pub const TITLE: &str = "Read my report with me";

/// Whether it has been shown to work, in the words the design-time prompts use for theirs.
pub const STATUS: &str = "Not tried yet.";

/// The prompt, as the person sends it.
pub const TEXT: &str = "\
Please read StackVet's report on this app with me. It is in the `stackvet-report` folder (or \
`securevibe-report`, from an older version): start with `compliance.md`, and use `security.md` \
for the details of anything it found. If there is no report there, tell me so, and that the app \
needs checking with StackVet first; do not guess what a report would say. I am not a programmer, \
so explain each technical word the first time you use it. Go in this order:

1. What was not checked, first. Read \"What was not examined\", the line that starts \"Not run \
this time\" if there is one, and the requirements counted as not verified or not yet placed. Tell \
me in plain words what each means for me: what could be wrong with the app that this report would \
not show. Do not skip this, and do not make it sound minor.
2. At most three things to do first. Take them from \"What to do next\" and the worst findings in \
\"The short version\", in the report's order. For each, tell me what it is, why it matters to the \
people who will use the app, and what to do about it. If the report gives fewer than three, say \
so; do not add more.
3. Then ask me what I would like to know more about.

Never tell me the app is secure, safe, compliant, or that it passed: the report does not say that, \
and it cannot. A requirement marked checked means a check looked and found nothing wrong over the \
coverage named beside it, not that the requirement is met; say it that way. Do not soften what \
the report says. Give numbers exactly as the report does. If you notice something yourself that \
the report does not say, tell me it is your own observation, not StackVet's.
";

/// The prompt with its mark after it, as `sv prompts report` prints it and the MCP server sends it.
pub fn with_mark() -> String {
    format!(
        "{}\n---\n{STATUS} A prompt is an instruction, not evidence: the report is the evidence, \
         and this asks your AI coding tool to explain it, not to add to it.\n",
        TEXT.trim_end()
    )
}
