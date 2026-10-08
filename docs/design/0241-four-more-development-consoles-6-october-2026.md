# Four more development consoles (6 October 2026)

`probe.development-console-open` (V15.2.3, V13.4.2) asked for two consoles: Werkzeug's and Rails' information page.
It now asks for four more. Each is known by words read from the tool's own source on its main branch that day, and
each answers only with the tool's development or debug mode on, so the citation of V13.4.2 still holds:

- **Go's profiler** at `/debug/pprof/`. Importing `net/http/pprof` is enough to put it on the default router, and it
  hands anybody the program's memory, goroutines, and command line. Known by the index page's title and its words
  "Types of profiles available:" (`indexTmplExecute`).
- **Laravel Ignition** at `/_ignition/health-check`. Its routes answer only with `app.debug` on, in a local or
  development environment, unless runnable solutions are switched on (`RunnableSolutionsGuard`). The same group holds
  `execute-solution`, the route behind CVE-2021-3129. Known by the one key its answer holds, `"can_execute_commands"`.
- **Symfony's profiler** at `/_profiler/empty/search/results?limit=10`. The recipe mounts it only in the dev
  environment. Its home page only redirects, to this address, which is asked for directly. Known by
  `<title>Symfony Profiler</title>` and `<h2>Profile Search</h2>`.
- **Phoenix LiveDashboard** at `/dev/dashboard/home`. The Phoenix generator mounts it only with `dev_routes` on, and
  it can kill the running system's processes. Known by its layout's `window.LiveDashboard` and its footer, "Phoenix
  LiveDashboard was made with love by".

As before, it is only ever a finding, and it is never judged by status alone. Pages that look alike are not taken for
these: a blog post quoting pprof's words, Laravel's 404 page, the profiler's title without its search, an app's own
dashboard, and a page showing LiveDashboard's script.

Left out: Spring Boot's Actuator. Exposing it is a management setting, not a debug mode, so V13.4.2 would not hold.

Broken on purpose 10 ways, each caught:
- each new console's words altered in turn (seven);
- every word required made any one word;
- the status ignored;
- one console's path changed.

The footer's words, and the changed path, went uncaught at first. Two cases were added for them: a page
showing LiveDashboard's script, and the six paths pinned as their sources serve them.
