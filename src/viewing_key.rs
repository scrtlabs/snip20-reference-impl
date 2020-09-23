use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Env;

use crate::rand::{sha_256, Prng};
use crate::utils::{create_hashed_password, ct_slice_compare};

pub const VIEWING_KEY_PREFIX: &str = "api_key_";
pub const VIEWING_KEY_LENGTH: usize = 44 /* length of base64 encoded 32 bytes */ + VIEWING_KEY_PREFIX.len();

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
pub struct ViewingKey(pub String);

impl ViewingKey {
    pub fn check_viewing_key(&self, hashed_pw: &[u8]) -> bool {
        let mine_hashed = create_hashed_password(&self.0);

        ct_slice_compare(mine_hashed.to_vec().as_slice(), hashed_pw)
    }

    pub fn new(env: &Env, seed: &[u8], entropy: &[u8]) -> Self {
        let mut rng_entropy: Vec<u8> = vec![];
        rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
        rng_entropy.extend_from_slice(&env.block.time.to_be_bytes());
        rng_entropy.extend_from_slice(&env.message.sender.0.as_bytes());
        rng_entropy.extend_from_slice(entropy);

        let mut rng = Prng::new(seed, rng_entropy.as_slice());

        let rand_slice = rng.rand_slice();
        let mut rand_vec = Vec::with_capacity(32);
        for n in &rand_slice {
            for n in &n.to_le_bytes() {
                rand_vec.push(*n);
            }
        }

        let key = sha_256(rand_vec.as_slice());

        Self(VIEWING_KEY_PREFIX.to_string() + &base64::encode(key))
    }

    pub fn to_hashed(&self) -> [u8; 24] {
        create_hashed_password(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == VIEWING_KEY_LENGTH
    }
}

impl fmt::Display for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
