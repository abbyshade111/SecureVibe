//! Writing the report folder for the AI coding tool: the folder confined below the app, then the one
//! sequence `sv report` keeps (`report_folder`).

use super::*;

impl Server {
    pub(super) fn write_report(&self, args: &Value, progress: &Progress) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        // The folder's default name is the new one, or the old one while only it exists (ADR-062).
        let default_out = sv_scan::ecosystems::default_report_dir_in(&app_dir);
        let default_out = default_out
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(sv_scan::ecosystems::DEFAULT_REPORT_DIR);
        let out = args
            .get("out")
            .and_then(Value::as_str)
            .unwrap_or(default_out);
        // Relative and downward only. The folder may not exist yet, so it cannot be canonicalized
        // before it is created; refusing `..` and absolute paths keeps it under the app instead.
        anyhow::ensure!(
            Path::new(out)
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
            "out has to be a folder inside the app, written without `..`: {out}"
        );
        // Components are not enough. A symlink inside the app has only `Normal` components and is
        // followed on the way out, so `out: "elsewhere"` wrote five files wherever it pointed and
        // said it had succeeded. Nor is creating the folder and then resolving it: `create_dir_all`
        // creates what is missing *through* a link before anything can look, so `out:
        // "elsewhere/a/b"` made `a/b` outside the root and only then was refused (BACKLOG,
        // "Hardening the MCP server", item 2). So the folder is made one level at a time, and a level
        // that is a link is refused before anything below it is created.
        let made = std::fs::symlink_metadata(app_dir.join(out)).is_err();
        let (out_dir, made_folders) = create_below(&app_dir, Path::new(out))?;
        // A write that fails takes away the folders it made, deepest first and only while empty, so
        // `out: "a/b/c"` leaves no `a/b` behind (item 24 of the review of 1 to 4 October). The report
        // folder itself goes with the lock (`claim_report_folder`); this is the ones above it.
        let written = self.write_report_into(&app_dir, out, out_dir, made, progress);
        if written.is_err() {
            for folder in made_folders.iter().rev() {
                let _ = std::fs::remove_dir(folder);
            }
        }
        written
    }

    /// `write_report`, once the folder `out` names has been made below the app as `out_dir`.
    pub(super) fn write_report_into(
        &self,
        app_dir: &Path,
        out: &str,
        out_dir: PathBuf,
        made: bool,
        progress: &Progress,
    ) -> Result<Value> {
        let resolved = out_dir
            .canonicalize()
            .with_context(|| format!("{} cannot be opened", out_dir.display()))?;
        anyhow::ensure!(
            resolved.starts_with(app_dir),
            "out resolves to {}, which is outside the app at {}",
            resolved.display(),
            app_dir.display()
        );
        let out_dir = resolved;
        // The same sequence `sv report` keeps, the same lock first, so the owner's run at a
        // terminal and this one cannot both write the folder (BACKLOG, "What the owner hit building
        // family-hub", item 2); what `sv` says on the way is collected for the reply.
        let elsewhere = "ask for a folder of its own with `out`";
        let mut notes = Vec::new();
        let crate::report_folder::ReportFolder {
            report,
            written,
            sealed,
        } = crate::report_folder::write_report_folder(
            app_dir,
            &out_dir,
            &format!("securevibe_write_report, through sv's MCP server (sv mcp), out \"{out}\""),
            elsewhere,
            made,
            || self.report_for(app_dir, progress),
            &mut |note| notes.push(note.to_owned()),
        )?;
        let written = written.names();
        let files: Vec<String> = written
            .iter()
            .map(|name| out_dir.join(name).display().to_string())
            .collect();
        // The notes are `sv`'s, but can quote the app: the lock file another run left in the
        // report folder names that run's command, and anything in the app can write that file.
        let text = sv_report::fence::fenced(|fence| {
            format!(
                "{}Wrote {} files to {}: {}. report.html is the one for a person to open. {} To keep the app and its report together or hand them on, securevibe_bundle makes one zip; offer it only if the person wants it.\n\n{}",
                notes
                    .iter()
                    .map(|n| format!("{}\n\n", fence.wrap(n)))
                    .collect::<String>(),
                files.len(),
                fence.wrap(&out_dir.display().to_string()),
                written.join(", "),
                if sealed {
                    "It is sealed with this computer's report key, so this server offers it as a \
                     report sv wrote while nothing changes it."
                } else {
                    "It could not be sealed, so this server will not offer it as a report sv wrote."
                },
                summary_with(&report, fence)
            )
        });
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "files": files },
            "isError": false,
        }))
    }
}
