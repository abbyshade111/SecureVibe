# Testing an app's AI feature: a fake model inside the fence, or garak

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Closed on 27 September
2026. **The owner's decision that day: garak is not taken up** ("I agree with the assessment that
   **Part status:** done, with the item
there are better options"). The test model inside the fence was built instead (below), and garak
would have needed a hole in the fence and the app's own API credit. Kept for the record. Asked by the owner on
26 September 2026 ("would adding a tool like garak help answer any of the AISVS requirements?") and
answered by session securevibe-e9.

**What garak could reach.** garak (NVIDIA's model scanner) sends attack prompts to a chat endpoint
and scores the replies; pointed at the app's own chat route, through a manifest entry in the shape
of the `[stack.run.users]` templates, it speaks to:

| Requirement | Asks | garak's part |
|---|---|---|
| C2.1.3 (L1) | prompt injection screened and blocked | its injection probes: a reply following the injected instruction is a finding |
| C2.1.2 (L1) | encoded or smuggled input caught | its encoding probes (base64 and the like) |
| C7.3.3 (L2) | model output cannot trigger outbound requests | its markdown image exfiltration probe |
| C11.1.3 (L1), C11.1.4 (L2) | the model tested against known attacks, and hardened | running it is that test; failures are findings |
| C2.1.8 (L3) | many-shot jailbreaks detected | only partly: it has jailbreak probes; whether it has a many-shot one is not checked |

Beside those, `sv`'s own log check could read the app's log after garak's attempts for C12.2.1 and
C12.2.3 (jailbreak and injection attempts detected and alerted on).

**Only ever findings.** garak samples and its detectors are heuristics: a clean run means these
prompts did not get through this time, not that the app resists them, and a hit can be a false
alarm, so the report has to show the prompt and the reply. The same rule as semgrep's AI rules
(`findings_against`).

**Two obstacles.**
1. **The fence.** The app runs where it cannot reach OpenAI, Anthropic, or anyone else, so its AI
   feature has no model to call, and garak would be testing an error page. Getting round it means
   letting the app reach its provider, a hole in the fence and the owner's decision.
   **Part status:** done, with the item
2. **Money.** Every garak prompt then spends the app's own API credit, and a full run is thousands
   of prompts. It would need a small probe set, a stated cap, and the owner asked each time, as for
   any paid step.
   **Part status:** done, with the item

**The alternative: a fake model inside the fence.** A small container speaking the provider's API
shape, as the test sign-in provider does for OIDC, that misbehaves on purpose: it obeys injected
instructions, repeats its system prompt, answers with a markdown image pointing outside, or answers
at great length. That tests the **app's own controls** rather than the model, which are what a small
app can actually meet, and it is free, needs no network, and gives exact answers that can credit:

- C7.3.2 (L2): `sv` plants a marker in what the model is sent, the fake model repeats it, and the
  marker must not reach the browser.
- C7.3.3 (L2): the fake answers with an image or link to an outside address; it must not be
  fetched or rendered.
- C7.1.2 (L1): the fake answers without end; the app has to cut it off.
- C2.1.3 (L1): an input carrying a known injection has to be refused before it reaches the model,
  which the fake can see by whether it was called.

Its limit: it needs the app to let its provider's address be set (`OPENAI_BASE_URL` and the like),
which most SDKs allow and some apps hard-code. That has to be stated in the manifest, and an app
that cannot be pointed at it is *not assessed*.

**Neither reaches** membership inference (C11.2.5), drift and hallucination monitoring (C12.3),
the training-data chapters, or most of the agent architecture in C9; those stay the owner's to answer.

**The owner's decision, 26 September 2026: the fake model first, not garak.** **The fake model
claimed the same day by session securevibe-e9**, for the four requirements above (C7.3.2, C7.3.3,
C7.1.2, C2.1.3). garak stays unclaimed and undecided. **The fake model is done the same day:** a `[stack.run.ai]`
section starts it, C7.1.2, C7.3.2, and C2.1.3 are credited or found, and C7.3.3 is found only.
AISVS goes from 6 to 10 of 191 that a check can settle. See DESIGN, "A test model inside the
fence".

**Thoughts.**

- *Session securevibe-e9.* The fake model first: free, exact, fenced, and able to credit the
  controls a small app owns. garak afterwards as an optional adapter, findings only, run only when
  the owner lets the app reach its provider for the run and agrees to what it spends, with the
  probe set and a cap named in the manifest.

  Asked by the owner for more ways to reach the remaining AISVS requirements, each built on
  machinery that exists or on the fake model once it does. None is claimed:
  - **C12.1.3, structured inference logs.** The fake model answers with a model name and token
    counts nobody else would use; the log check then looks for them in the app's output, as it
    does for its own markers (V16.2.1). Credit on presence.
  - **C12.2.1 and C12.2.3, injection attempts detected and alerted on.** After the C2.1.3 probe
    sends a textbook injection, the same log check looks for the app having flagged it.
  **C12.1.3 and C12.2.1 claimed on 26 September 2026 by session securevibe-e9**, at the owner's
  asking. C12.2.3 is not: it asks for rules that catch *coordinated* attempts, which one message
  cannot show, and it stays unclaimed. **Both done the same day:** C12.1.3 from the line carrying the token
  counts the test model reported, credited when structured and complete and a finding when found
  and short; C12.2.1 from a line saying the injection was caught. AISVS goes from 10 to 12 of 191.
  See DESIGN, "What the app wrote down about it".
  - **C11.2.2, rate limits on the inference route.** A number the owner states under `[policy]`,
    as `failed-sign-ins` is for V6.3.1, and one more request than that to the AI route, which
    costs nothing when the model is the fake one.
  - **C9.6.1, a kill switch.** The owner names the setting that halts the AI feature (an
    environment variable or a flag); the run starts the app with it on and asks the AI route,
    which must then answer without the fake model being called.
  - **C10.4.1 and C10.4.2, MCP responses screened.** The same idea as the fake model, for an app
    that is an MCP client: a fake MCP server in the fence whose `tools/list` breaks its own
    schema and whose `tools/call` carries an injected instruction, and the fake model reports
    whether either reached it.
  - **C9.3.4 and C9.3.7, what an agent may call.** The fake model asks for a tool call outside
    what the app declares, or to install a package that does not exist, and reports whether the
    app went ahead. Harder: the effect has to be observable, which depends on the app.

  **C11.2.2, C9.6.1, C10.4.1, and C10.4.2 claimed on 26 September 2026 by session securevibe-e9**,
  at the owner's asking, to be built in that order, one pull request each. C9.3.4 and C9.3.7 are
  not claimed: whether an app acted on a tool call it should have refused is seldom visible from
  outside it, and a check that cannot see the effect could only guess. **C11.2.2 done the same day:** one more
  message than `[policy] ai-requests-per-minute` states, after a minute's wait; credited only when
  the app's own page still answers afterwards. See DESIGN, "How often it can be asked". **C9.6.1
  done the same day:** a second copy of the app started with the owner's `kill-switch` setting
  must answer without calling the model. See DESIGN, "A kill switch, tried on a second copy". **C10.4.1
  and C10.4.2 done the same day:** a test MCP server beside the test model, whose tool answers with
  a result that breaks its schema and one carrying an injected instruction. See DESIGN, "MCP tool
  results, from a test MCP server". With that, everything claimed here is done.
