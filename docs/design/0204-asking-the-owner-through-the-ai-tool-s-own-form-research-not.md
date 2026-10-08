# Asking the owner through the AI tool's own form: research, not built (5 October 2026)

Backlog item 6 of the design-time list asked whether MCP *elicitation* could carry the owner's answers. Elicitation
lets a server such as `sv` ask the AI tool to show the person a small form; the answer comes back to the server. The
idea was that the AI tool cannot fill that form itself, so an answer given there could count as the owner's word, as
an answer sealed with `sv review` does. The owner asked for research first. This is what it found; nothing was built.

**The short answer: no, it cannot count as the owner's word.** Nothing in the protocol, and nothing in any AI tool
found, lets `sv` tell that a person filled the form rather than the AI tool. The premise in the backlog, "a form the AI
tool cannot fill", is not true of the tools as they are.

What the protocol says (read in the specification's source on GitHub, since its website was not reachable from here):

- **2025-06-18** introduced elicitation as a form. A server must not use it to ask for sensitive information. The
  person's answer is one of three: accept (with the answers), decline, or cancel. The tool should show which server is
  asking and let the person review and decline. The specification "does not mandate any specific user interaction
  model".
- **2025-11-25** added a second kind, which sends the person to a web address (for sign-ins and secrets that must not
  pass through the AI tool), and made the duties firm: the tool must show which server is asking, must offer decline
  and cancel, and must let the person review a form's answers before sending. It also says: "Servers MUST NOT rely on
  client-provided user identification without server verification, as this can be forged."
- **2026-07-28**, the latest, keeps the same rules and changes only the delivery: the server answers a tool call with
  "input required", and the tool sends the call again with the answers. That fits `sv`'s stateless server.
- No version requires that a person answer, or forbids the tool from answering for them.

Which AI tools support it (as of 5 October 2026): Claude Code (forms and web addresses, since version 2.1.76 in March
2026) and VS Code with Copilot (forms, since version 1.102 in July 2025), both read in their own release notes. Cursor
(since 1.5, August 2025, with users reporting the form not appearing on Windows and in one macOS window) and Codex CLI
(its code has it; the release was not confirmed) from secondary sources only. Windsurf is listed as supporting it by a
directory site, unconfirmed. Zed and Gemini CLI do not. Claude Desktop could not be confirmed either way.

Why an answer cannot be trusted as the person's: Claude Code's documentation describes hooks, scripts set in its
settings files, that can answer the form "without showing the user a dialog", or change the person's answer before it
is sent; in its non-interactive mode no form is ever shown. Those settings files sit in the project, where the AI tool
itself can write. So an "accept" may be a person, or a script the AI tool wrote. Codex's code has an OpenAI-only
verification step answered with a signature, which might prove a person was there; what makes the signature, and
whether it has shipped, could not be confirmed.

What `sv` does today: its MCP server speaks the four protocol versions through `initialize` and 2026-07-28 statelessly,
declares only tools, and has no elicitation code.

A possible next step, for the owner to decide: a middle tier, "confirmed in the AI tool's form, not sealed", always
shown as such in the report with the tool's name and version, and never meeting anything that now needs `sv review`.
A small trial would ask one yes-or-no design question only when the tool says it supports forms, record decline and
cancel as "not answered" (never as "no"), try it in Claude Code and VS Code, and include a test where a hook answers on
the person's behalf, to show `sv` records the same answer either way, which is why the label is needed. Whether that
tier is worth having, beside the plain answers in securevibe.toml that the tool writes and `sv review` that the person
seals, is the owner's choice.
