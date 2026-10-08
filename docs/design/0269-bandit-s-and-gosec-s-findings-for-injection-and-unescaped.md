# Bandit's and gosec's findings for injection and unescaped output name their requirement (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.4). A tool rule missing from `data/adapters.json` is still shown when it
fires, but cites nothing, so a Bandit finding for SQL built through Django's `extra` could sit in a report beside
"V1.2.4 checked". Each rule below was read in the tool's own source (Bandit's `plugins/`, gosec's `rules/`, 7 October
2026) and is now mapped, citing what `sv`'s own rule or Semgrep's equivalent cites:

| Rule | What it finds | Cites |
|---|---|---|
| Bandit B601 | a shell command built from a value and run through Paramiko | V1.2.5 |
| Bandit B610, B611 | SQL given to Django's `extra` and `RawSQL` | V1.2.4 |
| Bandit B701, B702, B703, B704 | Jinja2 with autoescape off, Mako, `mark_safe`, and `Markup` of text that is not fixed | V1.2.1 |
| gosec G203 | text that is not fixed marked as safe for a Go template | V1.2.1 |
| gosec G108 | `net/http/pprof` imported, serving profiling pages | V13.4.2 |
| Bandit B614 | a model loaded with `torch.load` | C4.1.2 |
| Bandit B615 | a Hugging Face download not pinned to a commit | C6.1.3 |

**Only ever as a finding.** All of them sit under `findings_against`, so a finding names the requirement it shows
failing and a clean run credits nothing new. Semgrep's equivalents credit, but Bandit's rules are narrower than the
requirements: B701 reads one Jinja2 setting, which is not output encoding everywhere. The counts of what can be checked
do not move.

**Named, citing nothing, and why.** B310 (`urlopen`) fires on every call, fixed addresses included, so citing V1.3.6
would mark safe code as failing. G106 (an SSH client accepting any host key) is about SSH, which the TLS requirements do
not cover. Both are in the map with a description, so a person reading the finding knows what it is.

**Two tests** in `crates/sv-check/tests/citations.rs`: every tool rule whose description is about injection or escaping
cites a requirement; and Bandit's and gosec's injection and escaping rules, listed from their sources, are all in the
map, citing something. The second is what catches a rule left out, which the first cannot see. Three guards broken in
turn, each caught: B610 taken out of the map, B701 citing nothing, and every new mapping taken out (the state before).
The citation guard caught four of the first descriptions sharing no words with V1.2.1; they now say "output encoding".
