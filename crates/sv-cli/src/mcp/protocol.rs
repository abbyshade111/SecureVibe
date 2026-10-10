//! The wire: newline-delimited JSON-RPC over stdio, read with a cap, and the reply shapes.

use super::*;

/// The longest request line read. A tool call is a few hundred bytes; this leaves room for any
/// request this server understands, and stops one line from taking all the memory there is.
pub(super) const MAX_REQUEST_BYTES: usize = 1 << 20;

/// Answers requests from `input` on `output`, one line each, until `input` ends.
///
/// Nothing a client sends ends the server or goes unanswered when it carried an id: a line too long
/// to read, or one that is not UTF-8, gets an error in reply rather than stopping the loop, which is
/// what `lines()` did with bytes that were not UTF-8.
pub fn serve(server: &Server, mut input: impl BufRead, output: impl Write) -> Result<()> {
    // Written to while a request is being answered (progress), and after it (the answer).
    let output = std::cell::RefCell::new(output);
    let tell = |note: Value| {
        let mut output = output.borrow_mut();
        // A notification that cannot be written is not worth ending the server for; the answer's
        // own write, below, says so if the output is really gone.
        let _ = writeln!(output, "{note}").and_then(|()| output.flush());
    };
    loop {
        let mut asked = None;
        let reply = match read_request(&mut input, MAX_REQUEST_BYTES).context("reading stdin")? {
            Request::End => return Ok(()),
            Request::TooLong => Some(
                error_reply(
                    Value::Null,
                    -32600,
                    &format!("a request is at most {MAX_REQUEST_BYTES} bytes; this one was longer"),
                )
                .to_string(),
            ),
            Request::NotText => {
                Some(error_reply(Value::Null, -32700, "a request has to be UTF-8 text").to_string())
            }
            Request::Line(line) if line.trim().is_empty() => None,
            Request::Line(line) => {
                let reply = server.handle_line_telling(&line, &tell);
                asked = Some(line);
                reply
            }
        };
        if let Some(reply) = reply {
            if let Some(line) = error_line(asked.as_deref(), &reply) {
                eprintln!("{line}");
            }
            let mut output = output.borrow_mut();
            writeln!(output, "{reply}").context("writing stdout")?;
            output.flush().context("flushing stdout")?;
        }
    }
}

/// The line `serve` writes on stderr when its answer is an error, or `None` (backlog 226, part 2,
/// item 19): the method or tool, and the kind of error, so the AI coding tool's own log of the server
/// keeps a record of it. No words of the app's are in it: a tool's name is kept only when it is a
/// plain name, and what the error says is left to the answer.
pub(super) fn error_line(request: Option<&str>, reply: &str) -> Option<String> {
    // Most answers are not errors, and some are large; only one that could be is read.
    if !reply.contains("\"isError\":true") && !reply.contains("\"error\":{") {
        return None;
    }
    let reply: Value = serde_json::from_str(reply).ok()?;
    let request: Option<Value> = request.and_then(|r| serde_json::from_str(r).ok());
    let plain = |s: &&str| {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'/')
    };
    let method = request
        .as_ref()
        .and_then(|r| r.get("method"))
        .and_then(Value::as_str)
        .filter(plain);
    if let Some(code) = reply.pointer("/error/code").and_then(Value::as_i64) {
        let kind = match code {
            -32700 => "not JSON",
            -32600 => "not a request it reads",
            -32601 => "no such method",
            -32602 => "parameters it could not use",
            RESOURCE_NOT_FOUND => "no such resource",
            _ => "another error",
        };
        return Some(format!(
            "sv mcp: {} was answered with protocol error {code} ({kind})",
            method.unwrap_or("a request")
        ));
    }
    let result = reply.get("result")?;
    if result.get("isError") != Some(&Value::Bool(true)) {
        return None;
    }
    let tool = request
        .as_ref()
        .and_then(|r| r.pointer("/params/name"))
        .and_then(Value::as_str)
        .filter(plain);
    let said = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = if said.contains("\n\nWhat to do: ") {
        "it could not do this, and said what to do"
    } else {
        "it could not do this"
    };
    Some(format!(
        "sv mcp: {} answered with an error: {kind}",
        tool.unwrap_or("a tool")
    ))
}

/// One line of input, as `serve` reads it.
pub(super) enum Request {
    Line(String),
    TooLong,
    NotText,
    End,
}

/// Reads up to the next newline, keeping at most `max` bytes. A longer line is read to its end and
/// thrown away, so the next request starts where it should.
pub(super) fn read_request(input: &mut impl BufRead, max: usize) -> std::io::Result<Request> {
    let mut kept = Vec::new();
    let mut too_long = false;
    let mut read_any = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            break;
        }
        read_any = true;
        let (chunk, ends_line) = match available.iter().position(|&b| b == b'\n') {
            Some(at) => (&available[..at], true),
            None => (available, false),
        };
        if kept.len() + chunk.len() > max {
            too_long = true;
        } else {
            kept.extend_from_slice(chunk);
        }
        let used = chunk.len() + usize::from(ends_line);
        input.consume(used);
        if ends_line {
            break;
        }
    }
    if !read_any {
        return Ok(Request::End);
    }
    if too_long {
        return Ok(Request::TooLong);
    }
    Ok(match String::from_utf8(kept) {
        Ok(line) => Request::Line(line),
        Err(_) => Request::NotText,
    })
}

pub(super) fn ok_reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub(super) fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Refuses an app folder with no stackvet.toml, naming the tool that writes one, and what to do
/// after: `again`, such as "check again".
pub(super) fn needs_manifest(app_dir: &Path, again: &str) -> Result<()> {
    if sv_manifest::locate(app_dir)?.is_some() {
        return Ok(());
    }
    Err(crate::Remedy::error(
        format!("there is no stackvet.toml in {}.", app_dir.display()),
        format!("Call stackvet_spec, write the file it describes into that folder, and {again}."),
    ))
}

/// What went wrong, the whole chain of it, and `sv`'s own next step when the error carries one
/// (`crate::Remedy`). The remedy is the innermost error, so its words end the chain; they are taken
/// off the end, and only when they are found there.
pub(super) fn split_remedy(e: &anyhow::Error) -> (String, Option<String>) {
    let whole = format!("{e:#}");
    match e.downcast_ref::<crate::Remedy>() {
        Some(remedy) if !remedy.next.is_empty() && whole.ends_with(&remedy.next) => (
            whole[..whole.len() - remedy.next.len()]
                .trim_end()
                .to_owned(),
            Some(remedy.next.clone()),
        ),
        _ => (whole, None),
    }
}

pub(super) fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

/// A result given by a tool's old name, once the tool was folded into another (backlog 0187, part
/// 10): the same result, ending with `sv`'s own line, outside any fence, naming the tool to call
/// instead.
pub(super) fn folded(mut result: Value, instead: &str) -> Value {
    if let Some(text) = result["content"][0]["text"].as_str() {
        let text = format!(
            "{text}\n\nThis tool's name is going away and it is no longer listed: call {instead}, \
             which gives the same."
        );
        result["content"][0]["text"] = json!(text);
    }
    result
}
