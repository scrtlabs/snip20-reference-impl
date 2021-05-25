#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`

// This file is copied from:
// https://github.com/baedrik/snip721-reference-impl/blob/e0654da5986aa59f4f252fcf479b1e9522cbbe68/src/expiration.rs
// Thanks Baedrik!

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::BlockInfo;
use std::fmt;

/// at the given point in time and after, Expiration will be considered expired
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Expiration {
    /// expires at this block height
    AtHeight(u64),
    /// expires at the time in seconds since 01/01/1970
    AtTime(u64),
    /// never expires
    Never,
}

impl fmt::Display for Expiration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expiration::AtHeight(height) => write!(f, "expiration height: {}", height),
            Expiration::AtTime(time) => write!(f, "expiration time: {}", time),
            Expiration::Never => write!(f, "expiration: never"),
        }
    }
}

/// default is Never
impl Default for Expiration {
    fn default() -> Self {
        Expiration::Never
    }
}

impl Expiration {
    /// Returns bool, true if Expiration has expired
    ///
    /// # Arguments
    ///
    /// * `block` - a reference to the BlockInfo containing the time to compare the Expiration to
    pub fn is_expired(&self, block: &BlockInfo) -> bool {
        match self {
            Expiration::AtTime(time) => block.time >= *time,
            Expiration::AtHeight(height) => block.height >= *height,
            Expiration::Never => false,
        }
    }

    pub fn as_some_time(&self) -> Option<u64> {
        match self {
            Expiration::AtTime(time) => Some(*time),
            // No way of converting, so it's safer to say that it has already expired
            Expiration::AtHeight(_) => Some(0),
            Expiration::Never => None,
        }
    }

    pub fn to_stored_expiration(&self) -> StoredExpiration {
        match self {
            Expiration::AtTime(time) => StoredExpiration {
                kind: ExpirationKind::AtTime.to_u8(),
                target: *time,
            },
            Expiration::AtHeight(height) => StoredExpiration {
                kind: ExpirationKind::AtHeight.to_u8(),
                target: *height,
            },
            Expiration::Never => StoredExpiration {
                kind: ExpirationKind::Never.to_u8(),
                target: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum ExpirationKind {
    AtTime = 0,
    AtHeight = 1,
    Never = 2,
}

impl ExpirationKind {
    fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredExpiration {
    pub kind: u8,
    pub target: u64,
}

impl Default for StoredExpiration {
    fn default() -> Self {
        Self {
            kind: ExpirationKind::Never.to_u8(),
            target: 0,
        }
    }
}

impl StoredExpiration {
    pub fn never() -> Self {
        Self {
            kind: ExpirationKind::Never.to_u8(),
            target: 0,
        }
    }

    pub fn at_some_time(time: Option<u64>) -> Self {
        if let Some(time) = time {
            Self {
                kind: ExpirationKind::AtTime.to_u8(),
                target: time,
            }
        } else {
            Self {
                kind: ExpirationKind::Never.to_u8(),
                target: 0,
            }
        }
    }

    pub fn to_expiration(&self) -> Expiration {
        match self.kind {
            x if x == ExpirationKind::AtTime.to_u8() => Expiration::AtTime(self.target),
            x if x == ExpirationKind::AtHeight.to_u8() => Expiration::AtHeight(self.target),
            x if x == ExpirationKind::Never.to_u8() => Expiration::Never,
            _ => panic!("unexpected value"),
        }
    }

    pub fn is_expired(&self, block: &BlockInfo) -> bool {
        match self.kind {
            x if x == ExpirationKind::AtTime.to_u8() => block.time >= self.target,
            x if x == ExpirationKind::AtHeight.to_u8() => block.height >= self.target,
            x if x == ExpirationKind::Never.to_u8() => false,
            _ => panic!("unexpected value"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_expiration() {
        let block_h1000_t1000000 = BlockInfo {
            height: 1000,
            time: 1000000,
            chain_id: "test".to_string(),
        };

        let block_h2000_t2000000 = BlockInfo {
            height: 2000,
            time: 2000000,
            chain_id: "test".to_string(),
        };
        let exp_h1000 = Expiration::AtHeight(1000);
        let exp_t1000000 = Expiration::AtTime(1000000);
        let exp_h1500 = Expiration::AtHeight(1500);
        let exp_t1500000 = Expiration::AtTime(1500000);
        let exp_never = Expiration::default();

        assert!(exp_h1000.is_expired(&block_h1000_t1000000));
        assert!(!exp_h1500.is_expired(&block_h1000_t1000000));
        assert!(exp_h1500.is_expired(&block_h2000_t2000000));
        assert!(!exp_never.is_expired(&block_h2000_t2000000));
        assert!(exp_t1000000.is_expired(&block_h1000_t1000000));
        assert!(!exp_t1500000.is_expired(&block_h1000_t1000000));
        assert!(exp_t1500000.is_expired(&block_h2000_t2000000));
    }
}
