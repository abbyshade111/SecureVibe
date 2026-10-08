# Static files from the app's folder: Rack's `Static` with no root, Spark, and Ktor (7 October 2026)

Three of the leftovers of `ast.static-files-from-app-folder` (V13.4.7), each read from its framework's own source:

- **Rack's `Static` with no `root:`** (rack `a9833c8`, `lib/rack/static.rb`).
  - **What it does:** with no root, it serves the folder the app was started in (`options[:root] || Dir.pwd`), but only
    for paths that begin with one of its `urls:`.
  - **What is reported:** a `use Rack::Static` whose only options are `urls:`, `index:`, `gzip:`, `cascade:`, and
    `cache_control:`, and whose `urls:` holds `""` or `"/"`, which serve every path. A call with any `root:` is left to
    the patterns that judge its root.
  - **What is not:** `urls: ["/media"]`, which serves only `./media/`, and a call with `header_rules:`, whose value the
    pattern does not read.
  - **How:** the regex engine `sv` uses has no look-ahead, so "no `root:`" is written as "nothing but these options".
- **Spark** (spark `1973e40`). `staticFiles.externalLocation(path)` and the older `externalStaticFileLocation(path)`
  make a `File` of the path as given (`resource/ExternalResource.java`).
  - **What is reported:** `"."`, `"./"`, or `System.getProperty("user.dir")`, from Java or from Kotlin.
  - **What is not:** `"/"` is the disk's root, not the app's folder; a witness holds that.
- **Ktor** (ktor `f76c50d`, `http/content/StaticContent.kt`).
  - **What is reported:** `staticFiles(remotePath, File("."))` and `staticPaths(remotePath, Path("."))`, or the folder
    the app was started from. Kotlin now has a query for this rule, where it said before that nothing was looked for.
  - **What is not:** the older `static { files(".") }`, since `files` resolves against `staticRootFolder` when one is
    set, and `.` may then be a folder of the app's own.

PHP code itself, and any folder named in settings or built at run time, are still not seen.

Eight guards broken in turn, each caught by the witnesses:
- the rule without its Rack part;
- a `root:` let into it;
- any `urls:` taken for every path;
- Spark left out of Java;
- the disk's root taken for the app's folder;
- Kotlin not read;
- Ktor given any folder;
- `staticPaths` left out.
