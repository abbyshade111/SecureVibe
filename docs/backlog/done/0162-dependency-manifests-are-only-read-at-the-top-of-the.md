# Dependency manifests are only read at the top of the repository

**Status:** done, as its markers read on 8 October 2026

Done on 25 September 2026.
`ecosystems::detect` walks the whole app folder (skipping installed dependencies and build output),
so a `client/` + `server/` app has its dependencies read, its pinning judged per project, and its
packages in the SBOM; every path it returns is relative to the app folder. A lockfile in a parent
folder pins a project only when that folder is a workspace root whose member list covers it (npm and
Yarn `workspaces`, `pnpm-workspace.yaml`, Cargo `[workspace]`, uv `[tool.uv.workspace]`): a stray
root lockfile pinning an unrelated project below it would be a wrong statement in the direction that
hides something. A nested project is named by its folder ("npm in server/") so two read as two.
Left over: the adapters still look for their tool's config (`pyproject.toml` and the like) at the
top only, and a Yarn Berry or Bun lockfile is not one `sv` reads. **Reading Yarn Berry and Bun
lockfiles claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick a
backlog item: pinning, the package list, and so the advisory check, for both. **Done the same day:** `bun.lock` and
`bun.lockb` count as lockfiles (every Bun app had been told it had none); `bun.lock` and Berry's
`yarn.lock` are read for the package list, and so for known vulnerabilities; `bun.lockb`, binary,
says it cannot be read and names the text lockfile. Checked against lockfiles Bun 1.4.2 and Yarn
4.18.1 wrote. See DESIGN, "Yarn Berry and Bun".
