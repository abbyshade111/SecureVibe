# A trial with packages leaves Haiku unable to try its app

**Status:** done, 8 October 2026

From the recipe trial: 3 of Haiku's 10 apps crashed on
faults trying them would have shown, and 2 pinned versions that do not exist. A builder could be given a folder of its
own to install into, with the network that needs; or the trial reads Haiku from the code alone, as this one did.
**Done on 8 October 2026 by later work, checked by session paper-facts**, at the owner's word ("please pick a backlog
item when you're ready"), from the roadmap (an item overtaken, which wants a done note rather than a build): the Haiku
5.5 trial (`docs/prompts/library-trial/haiku55.md`) ran the same recipe brief with Claude Haiku 5.5 and a fresh Haiku
4.5 control. Haiku 5.5's apps started under `sv run` 9 times in 10 and were signed in to 8, with no install failing;
the control's started 3 times and were signed in to none, failing as this item says (templates left broken, package
versions that do not exist, seeds that crashed). So the trials have a Haiku whose apps can be tried, and neither
remedy here is needed for it. For Haiku 4.5 the item stays true; giving a builder a networked folder to install into
would undo the fence the install step keeps (ADR-052), and is not proposed.
