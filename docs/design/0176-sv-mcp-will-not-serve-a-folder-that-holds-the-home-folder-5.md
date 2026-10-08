# `sv mcp` will not serve a folder that holds the home folder (5 October 2026)

R10 of the deep review: `sv mcp --root` refused the top of the computer's files and the home folder itself, and served
any folder above the home folder, `/home` or `/Users`, which hold every user's home folder, keys and mail included.

- **A root that holds the home folder is refused**, with the reason, as `/` and the home folder already were. The
  comparison is by whole folder names, so `/home/some` does not hold `/home/someone`, and a folder beside the home
  folder is still served.
- **With no home folder known** (`HOME` and `USERPROFILE` both unset), a folder just below the top, such as `/home`,
  is refused too, since it is where home folders are kept and nothing can tell it apart.

How it is held: `the_whole_computer_and_the_whole_home_folder_are_not_served` (`crates/sv-cli/src/mcp.rs`), which until
now asserted that `/home` was served. Three guards were undone in turn, a comparison by text rather than by folder
among them, and each was caught.
