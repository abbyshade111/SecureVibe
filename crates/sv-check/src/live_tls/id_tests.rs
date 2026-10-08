//! The DNS transaction id is not one a bystander can predict (the review of 8 October 2026, item
//! 6): until then it was the process id, which `ps` shows anyone, and an answer forged with it
//! would have been taken for the resolver's.

use super::query_id;

#[test]
fn the_query_id_is_not_the_process_id_and_changes_between_draws() {
    let predictable = std::process::id() as u16 ^ 0x5ab1;
    let draws: Vec<u16> = (0..16).map(|_| query_id()).collect();
    // Sixteen draws of sixteen bits all alike, or all equal to the old form, do not happen by
    // chance; one of them matching does (one in 65,536), so only the whole set is judged.
    assert!(
        draws.iter().any(|&id| id != predictable),
        "every draw was the old predictable id: {draws:?}"
    );
    assert!(
        draws.iter().any(|&id| id != draws[0]),
        "every draw was the same: {draws:?}"
    );
}
