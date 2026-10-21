//! Identifier generation: UUIDv7 batch ids (the server requires lowercase canonical v7) and
//! random hex boot ids. Randomness comes from the caller (`/dev/urandom` in main).

/// UUIDv7 from a millisecond timestamp and 10 random bytes (74 bits used).
pub fn uuid7(unix_ms: u64, rand: [u8; 10]) -> String {
    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&unix_ms.to_be_bytes()[2..8]);
    b[6] = 0x70 | (rand[0] & 0x0f);
    b[7] = rand[1];
    b[8] = 0x80 | (rand[2] & 0x3f);
    b[9..16].copy_from_slice(&rand[3..10]);
    let h = crate::sign::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// 16 hex chars from 8 random bytes; matches `^[A-Za-z0-9_.-]{1,64}$`.
pub fn boot_id(rand: [u8; 8]) -> String {
    crate::sign::hex(&rand)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid7_layout() {
        let id = uuid7(0x0192_7f3e_8a1b, [0xff; 10]);
        assert_eq!(id, "01927f3e-8a1b-7fff-bfff-ffffffffffff");
        let lo = uuid7(0, [0; 10]);
        assert_eq!(lo, "00000000-0000-7000-8000-000000000000");
    }

    #[test]
    fn uuid7_sorts_by_time() {
        assert!(uuid7(1_000, [9; 10]) < uuid7(1_001, [0; 10]));
    }

    #[test]
    fn boot_id_is_hex16() {
        assert_eq!(boot_id([0xab; 8]), "abababababababab");
    }
}
