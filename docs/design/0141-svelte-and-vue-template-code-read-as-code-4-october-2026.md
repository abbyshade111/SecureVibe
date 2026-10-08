# Svelte and Vue template code read as code (4 October 2026)

The rest of H2. A Svelte or Vue page's template runs code of its own, and `sv`'s rules now read it, with the page's
scripts, as JavaScript, or TypeScript when the page's script says `lang="ts"`.

**What is taken out.** In a Svelte page, every `{...}` outside the page's scripts, styles, and comments, in text and
in attributes alike, as Svelte's compiler reads them: an expression, `{#if}` and `{:else if}`, `{#each}` with its
list, its names, and its key, `{#await}` with its promise, `{#key}`, `{@html}`, `{@render}`, `{@const}`,
`{@debug}`, `{#snippet}`, and `{...spread}`. A brace inside a string or a template string does not end one. In a Vue
page, every `{{ }}`, and the value of every attribute named `@…`, `v-on:…`, `:…`, `.…`, `#…`, or `v-…`: a handler is
read as the body of a function, `v-for` as its names and its list, a slot's value as names, and the rest as
expressions, with character references such as `&quot;` decoded first, as Vue does. Names a block or a slot gives
values (`{#each items as { id }}`) are read as a function's parameters, so a default value in them is read too.
Each piece must be code the grammar reads. All of them are read as one program, each on its own line in the page, so a
finding names the page's line.

**Svelte's braces come before its markup.** The page's markup is read by a tokenizer that works the way a browser's
does, and a browser does not know Svelte: given `<button onclick={() => go()}>`, it reads a handler `{()` that ends
at the space, and the `>` of `=>` closes the tag. A handler that does not parse leaves the whole page unread, which
kept every rule silent for any Svelte 5 app with a handler written as an arrow function with a space in it. So each `{...}` is blanked out before the markup is read, as Svelte
itself reads it first.

**What is not read, and what that does.** A Vue template written in Pug or another language, a directive whose name
is worked out when the page runs (`:[key]`), a `{` never closed, a Svelte block this does not know, and a piece the
grammar cannot read. Such a page is named among the files not fully read, and, the part the first step left out,
each rule whose call is named in the page is held back, so it cannot say the app is clean. The page's scripts and
whatever else was read still count. As a check on the extraction, a page that the earlier test still says holds
template code, and from which nothing was taken out, is treated the same way.

**What this is not.** No rule looks for HTML put into a page unescaped, so `{@html}` and `v-html` are read only for
the code inside them; reading them is not a check of what they insert. The rules that read JavaScript now read more
of it in these pages, so a Svelte or Vue app may get findings it did not get before; each is in code the page runs.

Sixteen guards broken in turn, each caught in the end: the rules not held back, Svelte's braces not blanked out,
`{#each}`'s key dropped, `{:else if}` not known, Vue's handlers read as expressions, `v-for`'s list dropped, `{{ }}`
not read, character references not decoded, strings not skipped inside braces, comments not skipped, the template
always read as JavaScript, pieces not put on their own lines, a directive with a worked-out name believed, a Pug
template believed, an unreadable piece not counted, and the check on the extraction removed. The last two were
caught by nothing at first, because each covered for the other on a page with one piece; a page with one piece read
and one not, and a Vue page whose `<textarea>` holds an `@click` that Vue does not run, now catch each alone.
