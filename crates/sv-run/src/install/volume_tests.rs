//! The install volume's name is a SHA-256 (the review of 8 October 2026, item 6): a known answer,
//! computed apart from this code with Python's `hashlib` over the same bytes, so a change of hash
//! or of what is hashed shows.

use super::{Ecosystem, volume_name};

#[test]
fn the_volume_name_is_the_first_128_bits_of_a_sha_256_over_the_files() {
    let name = volume_name(
        Ecosystem::Python,
        "python:3.12-slim",
        &[b"six==1.16.0\n".to_vec()],
    );
    // sha256("py" 0 "python:3.12-slim" 0 len64("six==1.16.0\n") "six==1.16.0\n"), first 16 bytes.
    assert_eq!(name, "sv-deps-py-03cb5748a43686fb295f30bcca1b6055");
}

#[test]
fn the_name_is_one_docker_takes_for_a_volume() {
    let name = volume_name(Ecosystem::Node, "node:22", &[b"{}".to_vec()]);
    assert!(name.starts_with("sv-deps-node-"), "{name}");
    assert_eq!(name.len(), "sv-deps-node-".len() + 32, "{name}");
    assert!(
        name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "{name}"
    );
}
