//! Whether stackvet.toml's `[repository] not-the-app` list is used for this app (ADR-031).

use crate::{files, under_any};

/// The folders of `[repository] not-the-app` as they are used for this app: as given, or none when,
/// taken together, they would set apart every code file the app has, with why (ADR-031). The list is
/// written by the AI coding tool, and one that held all the app's code would leave nothing to say
/// what the app uses, so requirements its code shows to apply would read "does not apply". The whole
/// list goes, not one entry, since `src` and `lib` together can cover an app neither covers alone.
/// Also how many of the app's code files the list set apart, and how many it has.
pub fn not_the_app_in(
    listing: &files::Listing,
    folders: &[String],
) -> (Vec<String>, Option<String>, (usize, usize)) {
    let total = listing.code_files().count();
    let apart = listing
        .code_files()
        .filter(|f| under_any(&f.relative, folders))
        .count();
    if total > 0 && apart == total {
        let why = format!(
            "together they would set apart all {total} of the app's code file{}, leaving nothing to say \
             what the app uses, so the list is not used and every folder is read as the app",
            if total == 1 { "" } else { "s" }
        );
        return (Vec::new(), Some(why), (0, total));
    }
    (folders.to_vec(), None, (apart, total))
}
