# MITRE ATLAS: adopt in part, as references on the AI threats

The owner asked whether MITRE ATLAS, the catalog of attacks on AI systems, is worth bringing into the
threat model. Measured on 26 September 2026 against ATLAS content 2026.09 (format 6.0.0: 16 tactics,
120 techniques and 88 sub-techniques, 40 mitigations, 73 case studies). **Recommendation: adopt in
part.** Cite ATLAS techniques by ID on the six threats about AI, for a security reviewer reading the
report; do not copy ATLAS into `sv`, do not add checks from it, and do not show it to the owner in the
plain-language view. Nothing is built yet; the follow-up is on the backlog waiting for the owner's
yes.

### What it would add

- **A shared name for each AI threat, for the people who need one.** Each of the six AI threats has a
  clear ATLAS technique: T-07 prompt injection is AML.T0051 (LLM Prompt Injection); T-08 is AML.T0057
  (LLM Data Leakage) and AML.T0056 (Extract LLM System Prompt); T-09 is AML.T0034 (Cost Harvesting)
  and AML.T0029 (Denial of AI Service); T-10 is AML.T0055 (Unsecured Credentials); T-11 is AML.T0053
  (AI Agent Tool Invocation); T-12 is AML.T0048 (External Harms). A reviewer, an auditor, or an AI
  security team can look each one up and read ATLAS's case studies of it happening for real. That is
  the value, and it is modest.
- **Not new checks.** ATLAS describes attacks; what can be checked comes from its mitigations, and by
  this reading 35 of its 40 mitigations already have a home in an AISVS chapter (training data in C1,
  input validation in C2, supply chain in C6, output and guardrails in C7, agents in C9, monitoring in
  C12, and so on). The five without one (limiting what is published about a system, user training,
  deepfake detection, honeypots, and sensor fusion for predictive models) are policies or model
  engineering that nothing in an app's code or its running behavior can show. AISVS itself cites ATLAS
  in its chapter references, nine techniques and mitigations by ID, so the overlap is by design.
- **Most of ATLAS is about someone else's system.** 28 of the 120 techniques belong only to an
  attacker preparing (reconnaissance, resource development, adapting an attack), and many of the rest
  are about training or hosting a model. The apps `sv` sees call an AI service; they do not train one.

### What it would cost

- **Names drift; IDs hold.** Of the nine ATLAS entries AISVS cites, six have been renamed since (Evade
  ML Model is now Evade AI Model, Backdoor ML Model is now Manipulate AI Model, and so on), and all nine
  IDs still resolve. Citations must be by ID, against a named release, with the name read from that
  release rather than written by hand.
- **Monthly releases, and a format that moves.** Fourteen releases in the past year; the data format
  changed in May 2026 (5.x to 6.0.0), and the file older tools read is deprecated. Keeping a copy of
  the whole catalog (840 KB of YAML) current would be real upkeep for little use. Six IDs and their
  names, pinned to one release, is not.
- **Terms.** The data is published by MITRE in `mitre-atlas/atlas-data` under the Apache License 2.0,
  which allows this with attribution; ATLAS is MITRE's trademark and should be written "MITRE ATLAS".
- **Plain language.** Technique names are written for security people ("Cost Harvesting", "External
  Harms"). The owner's view keeps the threat model's own sentences; ATLAS belongs in the part a
  reviewer reads.
- **Only for apps that use AI.** The six threats are already gated on `ai`, `ai-actions`, and
  `ai-moderation`, so the references would appear only where they apply.

### Built, once the owner said yes

The owner said yes the same day. The references live in `data/atlas-references.json`, a file of
`sv`'s own, rather than in `data/knowledge/threats.json`: v1 shares that file, and the references
are `sv`'s report's business, so v1 has nothing to agree to. The file is compiled into `sv`, which
fetches nothing. It holds:

- **The pinned release** (2026.09) and the address of its file.
- **Eight technique names, read from that release** by `tools/atlas_references.py` and never typed.
  The script uses Python's standard library alone, so it reads each technique's ID and name from the
  lines that open its entry, and `--check-against-pyyaml` compares that with a full parse: all 208
  agree. Given `--release`, it moves to a newer release, prints every cited technique that was
  renamed, and refuses to write when one is gone.
- **Which technique each threat is, with a `because`.** The citation guard holds each phrase against
  the threat's own sentence and the technique's name, and a phrase with no word the comparison can use
  is refused, as for the requirements.

Loading refuses a reference that could not mean what it says: a threat that is not in the threat
model, or is not about AI; a technique whose name was not read from the release; a name kept for a
technique nothing cites; an empty `because`; and a release that is not the one the file was read
from. A test also holds that every threat about AI has a reference, so a new one cannot be added
without one.

In the report, a table after the threat table, "For a security reviewer: these threats in MITRE
ATLAS", lists them for the threats that apply, in the Markdown and HTML reports and in the JSON. It
says they are references and not checks, and a test shows that the same app has the same threat
statuses with and without them. An app with no AI has no such table.

Each of those refusals was removed in turn and the suite run: all six were caught. So was dropping
the one line in `sv report` that attaches the references, but only after a test was added for it:
the report library's tests passed without it, since they attach the references themselves. The
script was run against a doctored copy too: a cited technique that is not in the release is refused
and nothing is written, and a name that differs is reported as a rename and corrected.
