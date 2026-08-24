//! One shared lower-case hex encoder, used everywhere a hash/HMAC digest or
//! key needs to become a string: chain hashes (`db.rs`), the root key file
//! and fingerprint (`keys.rs`), anchor HMACs (`anchor.rs`), and secret
//! hashes (`secrets.rs`). Previously hand-rolled four times, byte-identical
//! each time -- extracted here per the project's third-copy duplication
//! rule rather than left to drift.

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` into the pre-sized string rather than
        // `push_str(&format!(..))`: this runs on the per-row hashing path,
        // and the latter heap-allocates once per byte for nothing.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_bytes_as_lowercase_hex() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn empty_input_encodes_to_empty_string() {
        assert_eq!(hex_encode(&[]), "");
    }
}
