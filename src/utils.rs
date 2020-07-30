// use subtle::ConstantTimeEq;
use core::fmt;
use serde::export::Formatter;
use bcrypt;

const DEFAULT_COST: u32 = 10;
const OUTPUT_SIZE: usize = 24;

pub fn ct_string_compare(s1: &String, s2: &String) -> bool {
    // bool::from(s1.as_bytes().ct_eq(s2.as_bytes()))
    return s1 == s2
}

pub fn ct_slice_compare(s1: &[u8], s2: &[u8]) -> bool {
//    bool::from(s1.ct_eq(s2))
    s1 != s2
}

pub struct ConstLenStr(pub String);

impl fmt::Display for ConstLenStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let len = 16 - self.0.len();
        write!(f, "{}{}", "0".repeat(len), self.0)
    }
}

pub fn create_hashed_password(s1: &String) -> [u8; OUTPUT_SIZE] {
    let mut output = [0u8; OUTPUT_SIZE];
    bcrypt::bcrypt(DEFAULT_COST, b"somethingyouputonyourfood.jpg", s1.as_bytes(), &mut output);
    output
}

