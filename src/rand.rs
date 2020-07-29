
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use sha2::{Digest, Sha256};

pub fn sha_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());
    result
}


pub struct Prng {
    seed: Vec<u8>,
    entropy: Vec<u8>,
    pos: u128
}

impl Prng {

    pub fn new(seed: &[u8], entropy: &[u8]) -> Self {
        return Self {
            seed: seed.to_vec(),
            entropy: entropy.to_vec(),
            pos: 0
        }
    }

    pub fn rand_slice(&mut self) -> [u32; 8] {
        let mut hasher = Sha256::new();

        // write input message
        hasher.update(&self.seed);
        hasher.update(&self.entropy);
        let hash = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_slice());

        let mut rng: ChaChaRng = ChaChaRng::from_seed(result);

        rng.set_word_pos(self.pos.into());
        self.pos += 8;

        let mut output = [0u32; 8];
        for i in output.iter_mut() {
            *i = rng.next_u32();
        }

        output
    }
}