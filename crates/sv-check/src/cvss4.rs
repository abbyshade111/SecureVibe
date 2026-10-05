//! CVSS v4 scores, as FIRST's reference calculator computes them (ADR-033).
//!
//! v4 is not a formula. A vector is placed in one of 270 groups, a "macrovector" of six digits, one for each of
//! six equivalence classes, and FIRST's experts gave each group a score (`cvss4_tables::LOOKUP`). The vector's own
//! score is that group's, moved down by how far the vector is from the group's most severe vectors, in proportion
//! to how far the next group down is. This follows the calculator's `cvss_score.js` step for step, in the same
//! order of arithmetic, so the rounding at the end lands where its does; a test holds it to that calculator's own
//! output.
//!
//! Base and threat metrics are read, as advisories publish them. Environmental metrics describe a deployment `sv`
//! knows nothing of and take their defaults: requirements high, nothing modified.

use crate::cvss4_tables::*;
use std::collections::BTreeMap;

/// The base metrics a v4 vector must carry, with the values each may take.
const BASE: [(&str, &str); 11] = [
    ("AV", "NALP"),
    ("AC", "LH"),
    ("AT", "NP"),
    ("PR", "NLH"),
    ("UI", "NPA"),
    ("VC", "HLN"),
    ("VI", "HLN"),
    ("VA", "HLN"),
    ("SC", "HLN"),
    ("SI", "HLN"),
    ("SA", "HLN"),
];

/// The CVSS v4 score of a vector, or `None` when it is not a whole v4 vector: every base metric once, with a
/// value it can take, and the threat metric `E` if any. A vector carrying environmental or supplemental metrics
/// is scored on its base and threat metrics, as v3 vectors are scored on their base.
pub fn score(vector: &str) -> Option<f64> {
    let rest = vector.trim().strip_prefix("CVSS:4.0/")?;
    let mut given: BTreeMap<&str, &str> = BTreeMap::new();
    for part in rest.split('/') {
        let (key, value) = part.split_once(':')?;
        if given.insert(key, value).is_some() {
            return None;
        }
    }
    let mut chosen: BTreeMap<&str, &str> = BTreeMap::new();
    for (metric, values) in BASE {
        let value = given.get(metric)?;
        if value.len() != 1 || !values.contains(value) {
            return None;
        }
        chosen.insert(metric, value);
    }
    match given.get("E").copied() {
        None | Some("X") | Some("A") => chosen.insert("E", "A"),
        Some(e @ ("P" | "U")) => chosen.insert("E", e),
        Some(_) => return None,
    };
    // Environmental requirements at their defaults, which the calculator reads as high.
    for metric in ["CR", "IR", "AR"] {
        chosen.insert(metric, "H");
    }
    Some(score_of(&chosen))
}

/// How severe each value is, in steps of 0.1, the most severe at 0.
fn level(metric: &str, value: &str) -> f64 {
    match (metric, value) {
        ("AV", "N") | ("PR", "N") | ("UI", "N") | ("AC", "L") | ("AT", "N") => 0.0,
        ("AV", "A") | ("PR", "L") | ("UI", "P") | ("AC", "H") | ("AT", "P") => 0.1,
        ("AV", "L") | ("PR", "H") | ("UI", "A") => 0.2,
        ("AV", "P") => 0.3,
        ("VC" | "VI" | "VA", "H") => 0.0,
        ("VC" | "VI" | "VA", "L") => 0.1,
        ("VC" | "VI" | "VA", "N") => 0.2,
        ("SC", "H") => 0.1,
        ("SC", "L") => 0.2,
        ("SC", "N") => 0.3,
        ("SI" | "SA", "S") => 0.0,
        ("SI" | "SA", "H") => 0.1,
        ("SI" | "SA", "L") => 0.2,
        ("SI" | "SA", "N") => 0.3,
        ("CR" | "IR" | "AR", "H") => 0.0,
        ("CR" | "IR" | "AR", "M") => 0.1,
        ("CR" | "IR" | "AR", "L") => 0.2,
        _ => f64::NAN,
    }
}

/// The six digits of the macrovector a vector falls in.
fn macrovector(m: &BTreeMap<&str, &str>) -> [usize; 6] {
    let is = |k: &str, v: &str| m.get(k) == Some(&v);
    let eq1 = if is("AV", "N") && is("PR", "N") && is("UI", "N") {
        0
    } else if (is("AV", "N") || is("PR", "N") || is("UI", "N")) && !is("AV", "P") {
        1
    } else {
        2
    };
    let eq2 = if is("AC", "L") && is("AT", "N") { 0 } else { 1 };
    let eq3 = if is("VC", "H") && is("VI", "H") {
        0
    } else if is("VC", "H") || is("VI", "H") || is("VA", "H") {
        1
    } else {
        2
    };
    // Safety (`S`) is an environmental value of SI and SA only, never set here.
    let eq4 = if is("SC", "H") || is("SI", "H") || is("SA", "H") {
        1
    } else {
        2
    };
    let eq5 = match m.get("E") {
        Some(&"P") => 1,
        Some(&"U") => 2,
        _ => 0,
    };
    let eq6 = if (is("CR", "H") && is("VC", "H"))
        || (is("IR", "H") && is("VI", "H"))
        || (is("AR", "H") && is("VA", "H"))
    {
        0
    } else {
        1
    };
    [eq1, eq2, eq3, eq4, eq5, eq6]
}

fn lookup(digits: [usize; 6]) -> Option<f64> {
    let key: String = digits.iter().map(|d| char::from(b'0' + *d as u8)).collect();
    LOOKUP
        .binary_search_by(|(k, _)| (*k).cmp(key.as_str()))
        .ok()
        .map(|i| LOOKUP[i].1)
}

/// The score, as `cvss_score` in the reference calculator computes it.
fn score_of(m: &BTreeMap<&str, &str>) -> f64 {
    if ["VC", "VI", "VA", "SC", "SI", "SA"]
        .iter()
        .all(|k| m.get(k) == Some(&"N"))
    {
        return 0.0;
    }
    let mv = macrovector(m);
    let [eq1, eq2, eq3, eq4, eq5, eq6] = mv;
    let Some(value) = lookup(mv) else {
        return f64::NAN;
    };
    let lower = |i: usize| {
        let mut d = mv;
        d[i] += 1;
        lookup(d)
    };
    let score_eq1 = lower(0);
    let score_eq2 = lower(1);
    let score_eq3eq6 = match (eq3, eq6) {
        (1, 1) | (0, 1) => lower(2),
        (1, 0) => lower(5),
        (0, 0) => {
            // Two ways down; the calculator takes the higher, and the right one when they tie or one is missing.
            let left = lower(5);
            let right = lower(2);
            match (left, right) {
                (Some(l), Some(r)) if l > r => Some(l),
                _ => right,
            }
        }
        _ => None,
    };
    let score_eq4 = lower(3);
    let score_eq5 = lower(4);

    // The most severe vectors of the macrovector, every way of composing them, in the calculator's order.
    let eq3eq6_maxes = MAX_EQ3_EQ6[eq3][eq6];
    let mut maxes: Vec<String> = Vec::new();
    for a in MAX_EQ1[eq1] {
        for b in MAX_EQ2[eq2] {
            for c in eq3eq6_maxes {
                for d in MAX_EQ4[eq4] {
                    for e in MAX_EQ5[eq5] {
                        maxes.push(format!("{a}{b}{c}{d}{e}"));
                    }
                }
            }
        }
    }
    const DISTANCES: [&str; 14] = [
        "AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR",
    ];
    // The first of them the vector is no more severe than, or failing that the last, as the calculator does.
    let mut distance = [0.0f64; 14];
    for max in &maxes {
        let parts: BTreeMap<&str, &str> =
            max.split('/').filter_map(|p| p.split_once(':')).collect();
        for (i, metric) in DISTANCES.iter().enumerate() {
            let ours = m.get(metric).copied().unwrap_or("");
            let theirs = parts.get(metric).copied().unwrap_or("");
            distance[i] = level(metric, ours) - level(metric, theirs);
        }
        if !distance.iter().any(|d| *d < 0.0) {
            break;
        }
    }
    let [av, pr, ui, ac, at, vc, vi, va, sc, si, sa, cr, ir, ar] = distance;
    let current_eq1 = av + pr + ui;
    let current_eq2 = ac + at;
    let current_eq3eq6 = vc + vi + va + cr + ir + ar;
    let current_eq4 = sc + si + sa;

    let step = 0.1;
    let depth_eq1 = f64::from(DEPTH_EQ1[eq1]) * step;
    let depth_eq2 = f64::from(DEPTH_EQ2[eq2]) * step;
    let depth_eq3eq6 = f64::from(DEPTH_EQ3_EQ6[eq3][eq6]) * step;
    let depth_eq4 = f64::from(DEPTH_EQ4[eq4]) * step;

    let mut existing = 0u32;
    let mut total = 0.0f64;
    let mut normalized = [0.0f64; 5];
    for (i, (next, current, depth)) in [
        (score_eq1, current_eq1, depth_eq1),
        (score_eq2, current_eq2, depth_eq2),
        (score_eq3eq6, current_eq3eq6, depth_eq3eq6),
        (score_eq4, current_eq4, depth_eq4),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(next) = next {
            existing += 1;
            normalized[i] = (value - next) * (current / depth);
        }
    }
    if let Some(next) = score_eq5 {
        // EQ5's proportion is always 0, so it adds only to the count.
        existing += 1;
        normalized[4] = (value - next) * 0.0;
    }
    if existing > 0 {
        total = (normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4])
            / f64::from(existing);
    }
    let value = (value - total).clamp(0.0, 10.0);
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_textbook_vectors_score_as_first_publishes_them() {
        // The v4 specification's own example of a network attack losing everything: 9.3.
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            Some(9.3)
        );
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"),
            Some(0.0),
            "no impact anywhere is no score"
        );
    }

    #[test]
    fn a_vector_that_is_not_a_whole_v4_vector_is_not_scored() {
        for vector in [
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:Q",
            "CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "",
        ] {
            assert_eq!(score(vector), None, "{vector}");
        }
    }

    /// The reference scores in the file at `path`, as `vector score` lines.
    fn reference(path: &std::path::Path) -> Vec<(String, f64)> {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let (v, s) = l.rsplit_once(' ').unwrap();
                (v.to_owned(), s.parse().unwrap())
            })
            .collect()
    }

    fn differing(pairs: &[(String, f64)]) -> Vec<String> {
        pairs
            .iter()
            .filter(|(v, s)| score(v) != Some(*s))
            .map(|(v, s)| format!("{v}: reference {s}, sv {:?}", score(v)))
            .collect()
    }

    #[test]
    fn every_score_equals_the_reference_calculator_s() {
        // tools/cvss4_tables.py asked FIRST's own JavaScript for these.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cvss4-reference.txt");
        let pairs = reference(&path);
        assert!(
            pairs.len() > 1000,
            "the reference file is short: {}",
            pairs.len()
        );
        let wrong = differing(&pairs);
        assert!(
            wrong.is_empty(),
            "{} differ:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn every_vector_there_is_equals_the_reference_when_asked() {
        // All 419,904 base and threat vectors, from `tools/cvss4_tables.py --all`, when SV_CVSS4_ALL names the
        // file; too large to keep in the repository.
        let Some(path) = std::env::var_os("SV_CVSS4_ALL") else {
            return;
        };
        let pairs = reference(std::path::Path::new(&path));
        let wrong = differing(&pairs);
        assert!(
            wrong.is_empty(),
            "{} of {} differ:\n{}",
            wrong.len(),
            pairs.len(),
            wrong
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
