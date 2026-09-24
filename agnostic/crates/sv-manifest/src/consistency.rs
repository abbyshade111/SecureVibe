//! Checks the manifest against itself.
//!
//! Some claims have no applicability rule keyed on them — `payments` and `scheduler` among them —
//! so being wrong about one changes no requirement. That does not make being wrong about one
//! harmless: a manifest saying the app takes no money while the code imports Stripe is a manifest
//! that does not describe the app, and the consequence shows up somewhere else entirely.
//!
//! Where it shows up is the data categories, which *do* change things: they set the ASVS target
//! level. An app taking payments holds financial data; an app with sign-in holds credentials —
//! v1's profile says so in as many words, "credentials (always present when sign-in is on)". So
//! these checks connect a claim that gates nothing to the answer that gates a great deal.
//!
//! They are questions, not corrections. `sv` does not edit the manifest or quietly raise the level
//! on the owner's behalf: it says what looks inconsistent and what the consequence would be.

use crate::{Manifest, ResolvedClaim};
use sv_frameworks::Condition;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inconsistency {
    /// The claim that prompted it.
    pub condition: Condition,
    /// The data category that looks missing.
    pub missing_category: &'static str,
    /// What this would change, in plain language.
    pub consequence: String,
}

impl Inconsistency {
    pub fn explain(&self) -> String {
        format!(
            "This app {}, but `{}` is not in its data categories. {}",
            match self.condition {
                Condition::Payments => "takes payments",
                Condition::Auth => "has sign-in",
                Condition::Uploads => "accepts file uploads",
                other => other.name(),
            },
            self.missing_category,
            self.consequence
        )
    }
}

/// Claims whose truth implies a data category, and what adding it would do.
const IMPLIED: &[(Condition, &str, &str, bool)] = &[
    (
        Condition::Payments,
        "financial",
        "Taking money means holding financial data, which raises the ASVS target to level 2 and \
         brings a great many more requirements into scope.",
        true,
    ),
    (
        Condition::Auth,
        "credentials",
        "Anyone signing in has a password or a token to protect, so `credentials` belongs in the \
         list. It does not change the target level on its own.",
        false,
    ),
    (
        Condition::Uploads,
        "files",
        "Files people upload are data this app holds. It does not change the target level on its \
         own.",
        false,
    ),
];

/// Everything the manifest says that does not sit well with something else it says.
///
/// Driven by the *resolved* claims, not the written ones, so a claim the code contradicted counts:
/// an app whose manifest denies payments while importing Stripe still needs this asked.
pub fn check(manifest: &Manifest, resolved: &[ResolvedClaim]) -> Vec<Inconsistency> {
    let mut out = Vec::new();
    let categories: Vec<String> = manifest
        .data
        .categories
        .iter()
        .map(|c| c.to_lowercase())
        .collect();

    for (condition, category, consequence, raises_level) in IMPLIED {
        let holds = resolved
            .iter()
            .find(|r| r.condition == *condition)
            .and_then(|r| r.effective)
            .unwrap_or(false);
        if !holds || categories.iter().any(|c| c == category) {
            continue;
        }
        // `financial` and `payment-card` both cover the payments case; either one satisfies it.
        if *condition == Condition::Payments && categories.iter().any(|c| c == "payment-card") {
            continue;
        }
        // Saying the level would change when it is already 2 would be untrue.
        let consequence = if *raises_level && manifest.target_level() == 2 {
            "This app is already assessed at level 2, so adding it changes no requirement — but \
             the categories should still describe what the app holds."
                .to_owned()
        } else {
            (*consequence).to_owned()
        };
        out.push(Inconsistency {
            condition: *condition,
            missing_category: category,
            consequence,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Audience, resolve};

    fn resolved_with(manifest: &Manifest, found: Condition) -> Vec<ResolvedClaim> {
        resolve(manifest, &|c| (c == found).then_some(true)).1
    }

    #[test]
    fn payments_found_in_code_asks_about_the_data_categories() {
        // The case that prompted this. `payments` gates no requirement, so the contradiction
        // alone changes nothing — but the app plainly holds financial data and the categories say
        // it does not, and that answer does change things.
        let mut m = Manifest::default();
        m.app.audience = Audience::JustMe; // level 1, so the consequence is real
        let resolved = resolved_with(&m, Condition::Payments);
        let found = check(&m, &resolved);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].missing_category, "financial");
        assert!(
            found[0].explain().contains("level 2"),
            "{}",
            found[0].explain()
        );
    }

    #[test]
    fn either_financial_or_payment_card_settles_it() {
        let mut m = Manifest::default();
        m.app.audience = Audience::JustMe;
        for category in ["financial", "payment-card"] {
            m.data.categories = vec![category.to_owned()];
            let resolved = resolved_with(&m, Condition::Payments);
            assert!(
                check(&m, &resolved)
                    .iter()
                    .all(|i| i.condition != Condition::Payments),
                "{category} should satisfy the payments check"
            );
        }
    }

    #[test]
    fn it_does_not_claim_a_level_change_that_would_not_happen() {
        // An app already at level 2 gains no requirements by adding the category, and saying it
        // would is the kind of small overstatement this project keeps hunting.
        let mut m = Manifest::default();
        m.data.categories = vec!["health".into()]; // already level 2
        assert_eq!(m.target_level(), 2);
        let resolved = resolved_with(&m, Condition::Payments);
        let found = check(&m, &resolved);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].consequence.contains("already assessed at level 2"),
            "{}",
            found[0].consequence
        );
    }

    #[test]
    fn a_claim_that_does_not_hold_asks_nothing() {
        let mut m = Manifest::default();
        m.app.audience = Audience::JustMe;
        m.capabilities.payments = Some(false);
        let (_, resolved) = resolve(&m, &|_| Some(false));
        assert!(check(&m, &resolved).is_empty());
    }

    #[test]
    fn sign_in_implies_credentials() {
        let mut m = Manifest::default();
        m.app.audience = Audience::JustMe;
        m.capabilities.auth = Some(true);
        let (_, resolved) = resolve(&m, &|_| None);
        let found = check(&m, &resolved);
        assert!(
            found.iter().any(|i| i.missing_category == "credentials"),
            "{found:?}"
        );
        // And it must not pretend this changes the level, because it does not.
        let credentials = found
            .iter()
            .find(|i| i.missing_category == "credentials")
            .unwrap();
        assert!(
            credentials
                .consequence
                .contains("does not change the target level")
        );
    }
}
