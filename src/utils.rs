use bcrypt_pbkdf::bcrypt_pbkdf;
use subtle::ConstantTimeEq;

// 5 rounds == ~300M gas (doesn't work with query) - creation/validation takes ~1.5s
// 2 rounds == ~120M gas (works with query) - creation/validation takes ~1s
const DEFAULT_COST: u32 = 2;
const OUTPUT_SIZE: usize = 24;
const SALT: &[u8] = b"bestspiceintheEU";

pub fn ct_slice_compare(s1: &[u8], s2: &[u8]) -> bool {
    bool::from(s1.ct_eq(s2))
}

pub fn create_hashed_password(s1: &str) -> [u8; OUTPUT_SIZE] {
    let mut output = [0u8; OUTPUT_SIZE];
    let _ = bcrypt_pbkdf(s1, SALT, DEFAULT_COST, &mut output);
    output
}
