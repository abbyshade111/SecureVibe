//! What arrives on the MCP server's input, as an AI coding tool, or anything that can write to it,
//! sends it: the server must answer, stay silent, or stop with an error, never panic. It serves an
//! empty folder, so a tool call is refused for want of a `stackvet.toml` rather than starting a
//! check.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn server() -> &'static sv_cli::mcp::Server {
    static SERVER: OnceLock<sv_cli::mcp::Server> = OnceLock::new();
    SERVER.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("sv-fuzz-mcp-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        sv_cli::mcp::Server::new(&root).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let mut answers = Vec::new();
    let _ = sv_cli::mcp::serve(server(), data, &mut answers);
});
