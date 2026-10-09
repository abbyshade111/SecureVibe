//! What the AI coding tool is told to pass to `--fail-on` is a value `sv` takes. In `exit.rs`'s own tests
//! until 9 October 2026; here since the exit codes are the library's and the MCP server is the program's.

#[test]
fn every_fail_on_the_ai_tool_is_told_to_use_is_one_sv_takes() {
    // Gap analysis 6.3: the default exit is 0 with findings (ADR-029), so what an AI coding tool
    // reads before writing a CI workflow names `--fail-on`. A value `sv` refused would leave
    // the workflow failing on every run, or worse, edited until it no longer asks.
    for (whose, text) in [
        ("the MCP server's instructions", crate::mcp::INSTRUCTIONS),
        ("the specification", sv_manifest::spec::INSTRUCTIONS),
    ] {
        let named: Vec<&str> = text
            .split("--fail-on ")
            .skip(1)
            .map(|rest| {
                rest.split(|c: char| c.is_whitespace() || c == '`' || c == ')')
                    .next()
                    .unwrap_or("")
            })
            .collect();
        assert!(
            named.contains(&"attention:high"),
            "{whose} must name --fail-on attention:high: {named:?}"
        );
        for value in named {
            sv_cli::exit::FailOn::parse(value)
                .unwrap_or_else(|e| panic!("{whose} names --fail-on {value}: {e}"));
        }
    }
}
