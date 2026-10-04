# Prompts for your AI coding tool

These are instructions you can paste into the AI tool that builds your app (Claude Code, Cursor, Copilot, or
another). Each one asks for something SecureVibe checks, and each one has been tried: the same small app was built
twice, once with the prompt and once without, and `sv` checked both. A prompt is listed under "Shown to work" only
when the build with it passed its check and the build without it failed. The rest are listed apart, with what
happened, because a prompt that has not been shown to change anything should not be trusted as if it had.

The prompts are written in this project's own words. Some were inspired by the Cloud Security Alliance's
[Secure Vibe Coding Guide](https://cloudsecurityalliance.org/blog/2025/04/09/secure-vibe-coding-guide)
(K. Huang, 9 April 2025); none of its text is copied. The same prompts, with the checks behind them, are in
`data/prompts.json`.

**How they were tested (3 October 2026).** The test app was a notes app in Python (Flask and SQLite) with
sign-up and sign-in, formatted notes, search, file attachments, an export that runs another program, a redirect
back after signing in, and a welcome email that needs an API key. Fresh helper agents of the same Claude model
built it once with no prompt, and once for each prompt, each in a folder of its own. One build each is a small
sample: a prompt that showed nothing here may still help on another app or with another tool.

## Shown to work

### Describe the app to SecureVibe before writing code

> Before writing any code, run `sv init` in the project folder and fill in the securevibe.toml it creates: what
> the app does, who uses it, its languages, how to start it, and which of the listed capabilities it has. For any
> capability you are not sure about, delete the line instead of writing false. Keep the file up to date whenever
> the app gains or loses a capability.

*What it showed:* with the prompt, the app had a filled-in `securevibe.toml` and `sv report` checked it. Without
it, there was no such file, and `sv report` could not check the app at all. Deleting an unsure line matters:
a capability left out is reported as "not assessed", which is honest, while `false` claims the requirements that
depend on it do not apply.

### Keep the app in git from the first file

> Make the project folder a git repository before writing the first file (`git init`), add a .gitignore straight
> away that leaves out .env files, keys, and installed dependencies, and commit after each step that works.

*Requirement:* ASVS V13.3.1 (secrets are kept out of the code and its history).
*What it showed:* with the prompt, the app was a git repository with a `.gitignore`, and `sv`'s check for a
password or key committed to the history ran. Without it, the folder was not a git repository, so that check
could not run.

## Tried, not shown to work

Each of these asks for something sound, and each build that used it did what it asked. None is offered as tested,
because the test could not show the prompt made the difference.

| Prompt | Requirement | What happened |
|---|---|---|
| Keep keys and passwords out of the code | V13.3.1 | The build without the prompt already read its key from the environment. |
| Run other programs without a shell | V1.2.5 | The build without the prompt already ran the export with no shell. |
| Store passwords with a password-hashing function | V11.4.1, V11.4.4 | The build without the prompt already used a proper password hash. |
| Clean formatted text before showing it | V1.3.1 | The build without the prompt allowed only a few safe tags itself; `sv`'s check reads which libraries an app uses, so it could not judge that build either way. |
| Build every database query with placeholders | V1.2.4 | The build with the prompt followed it, and `sv` wrongly flagged two of its safe queries. A fault in `sv`, recorded in the backlog. |
| Save files under names the app makes | V5.3.2 | The build with the prompt followed it, and `sv` wrongly flagged the file path it read back from its own database. A fault in `sv`, recorded in the backlog. |
| Send people back only to pages on the same site | V3.7.2 | Both builds checked the address before redirecting, and `sv` flagged both: it cannot yet tell a checked redirect from an unchecked one. Recorded in the backlog. |

The full wording of each is in `data/prompts.json`.
