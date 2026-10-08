# Four ways of writing a path or a redirect that the rules missed

The path rule (V5.3.2) and the redirect rule (V3.7.2) were written from the most common way to write
each call, and four others were listed as left over. They are data entries, not new code:

- **Express's `res.redirect(301, url)`.** The status comes first and is a number, so the query
  looked at the number and saw a literal. A second pattern takes the argument after a leading number.
- **Ruby's `send_file params[:path]`.** It is called with no receiver, so the pattern that needs
  `File.` or `IO.` never saw it. A second pattern captures the method name as both the function and
  the "module", so the module filter still applies to every match. `Rails.root.join('public', 'a.pdf')`
  with only quoted parts is a safe idiom. (`redirect_to` was already covered; the backlog was wrong.)
- **Java's `Paths.get(name)` and `Path.of("uploads", name)`.** The Java query looked only at
  `new File(…)` and similar. A second pattern takes method calls on `Paths` or `Path`, and checks
  every argument, because the value is often the second part, not the first. `m.get(n)` on anything
  else is not a finding.
- **PHP's `include $page`.** `include`, `include_once`, `require`, and `require_once` are language
  constructs, not calls, so no call pattern could see them. They have their own patterns now.
  `__DIR__ . '/config.php'` and `dirname(__FILE__) . '/lib.php'` are safe idioms.

Each fix has a found and a not-found case. Each of the eight parts was removed in turn: the second
Express pattern, the receiverless Ruby pattern, `send_file` as a module, the `Rails.root` exception,
the Java module filter, checking every Java argument, the PHP include pattern, and the `__DIR__`
exception. Every one was caught. No requirement's count changes: this makes two existing rules find
more.
