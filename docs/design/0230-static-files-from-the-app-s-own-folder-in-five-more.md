# Static files from the app's own folder, in five more languages (6 October 2026)

`ast.static-files-from-app-folder` (V13.4.7, findings only) looks for a web framework's static-file handler that is
given the folder the code is in, or the folder the app was started from. Either one hands out the source, the
settings, and a `.env` file beside them. When it was built it read JavaScript, TypeScript, Python, Go, and shell, and
left PHP, Ruby, Java, C#, and Rust as not done. Each handler below was read from the project's own source on
6 October 2026, as the first languages' were. The rule stays pure data in `data/ast-rules.json`: a query per language,
the handler names, and the arguments that name the app's own folder.

- **Ruby.**
  - Sinatra's `set :public_folder` (by default `root/public`, `sinatra/base.rb`).
  - Rack's `Rack::Static` with `root:` (`rack/static.rb`).
  - `Rack::Files.new`.
  - Each counts when given `.`, `__dir__`, the file's own folder, `Dir.pwd`, or `root`.
- **Java.**
  - Spring's `addResourceLocations` given `"file:./"` or `"file:" + System.getProperty("user.dir")`.
  - Javalin's `staticFiles.add(".", Location.EXTERNAL)` (`StaticFilesConfig.kt`).
- **C#.** `UseStaticFiles`, `UseFileServer`, or `UseDirectoryBrowser`, whose options carry a `FileProvider`, given a
  `PhysicalFileProvider` for any of:
  - the current folder;
  - the build output (`AppContext.BaseDirectory`);
  - the content root, where `appsettings.json` is.
- **Rust.**
  - tower-http's `ServeDir::new(".")`.
  - actix-files' `Files::new(path, "./")`, which its own documentation says serves the current working directory.
  - warp's `fs::dir(".")`.
- **PHP.** PHP's own server, `php -S`, serves the folder it was started in when it is given no `-t`
  (`php_cli_server.c` falls back to the working folder). It is read where it is run, in shell scripts, as
  `python -m http.server` already was. `-t .` counts as the same folder; `-t public` does not.

Every language has witnesses both ways: the unsafe form and its neighbors that are fine. Examples of the fine ones:
- `File.join(__dir__, "public")`;
- `"classpath:/static/"`;
- `UseStaticFiles()` with no provider;
- `ServeDir::new("assets")`;
- `php -S … -t ./public`;
- a list's own `add(".")`.

Broken on purpose sixteen ways:
- each new language's pattern made to match nothing, or anything;
- `php -S` not looked for;
- `-t .` counted as safe;
- `-t` never counted as safe;
- `Rack::Files.new` not looked for;
- `Dir.pwd` not counted;
- the content root not counted;
- Spring's `user.dir` not looked for;
- Javalin's `Location.EXTERNAL` not required.

The Spring `user.dir` break was caught by nothing at first. The plain `"file:./"` pattern also matched `"file:" +`
followed by anything, so it would have reported `addResourceLocations("file:" + uploads)`, which serves a folder of
its own. The pattern now requires the string to end there. A witness holds that, and the `user.dir` break is caught.

A witness written as `ServeDir::new(env!("CARGO_MANIFEST_DIR"))` also set off `ast.file-path-from-value`, which takes
`env!` for a value. That form was left out of this rule rather than written unwitnessed, and the other rule's mistake
is in the backlog.

Still not seen:
- Rack's `Static` with no `root:`. Its default is the folder the app was started in, but only below the `urls:` it is
  given, which a pattern cannot weigh.
- Spark Java, and Kotlin's Ktor, not read here.
- Static files set up in PHP code itself.
- Any folder named in settings or built at run time.
