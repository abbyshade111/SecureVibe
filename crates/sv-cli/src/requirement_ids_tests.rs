//! A gap's requirements are the ids its own list names, split and trimmed, and nothing else
//! (backlog 226, part 2, item 20).

use super::*;

#[test]
fn a_list_of_ids_is_split_and_trimmed_and_empties_dropped() {
    assert_eq!(
        requirement_ids("V8.2.2, V3.5.1,C7.1.1 , ,"),
        ["V8.2.2", "V3.5.1", "C7.1.1"]
    );
    assert!(requirement_ids("").is_empty());
}
