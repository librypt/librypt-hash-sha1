use librypt_hash::{Hash, HashFn};

/// SHA-1 hash function.
///
/// WARNING: SHA-1 is cryptographically broken and unsuitable for further use.
pub struct Sha1 {
    total: u64,
    state: [u32; 5],
    buffer: (usize, [u8; 64]),
}

impl Sha1 {
    pub const STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    fn compute(&mut self) {
        let chunk = &self.buffer.1;

        let mut state = self.state;
        let mut words = [0u32; 80];

        for (i, word) in chunk.chunks(4).enumerate() {
            words[i] = u32::from_be_bytes(word.try_into().unwrap());
        }

        // extend words
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        for i in 0..80 {
            let f: u32;
            let k: u32;

            if i < 20 {
                f = (state[1] & state[2]) ^ ((!state[1]) & state[3]);
                k = 0x5A827999;
            } else if i < 40 {
                f = state[1] ^ state[2] ^ state[3];
                k = 0x6ED9EBA1;
            } else if i < 60 {
                f = (state[1] & state[2]) ^ (state[1] & state[3]) ^ (state[2] & state[3]);
                k = 0x8F1BBCDC;
            } else {
                f = state[1] ^ state[2] ^ state[3];
                k = 0xCA62C1D6;
            }

            let temp = (state[0].rotate_left(5))
                .wrapping_add(f.wrapping_add(state[4].wrapping_add(k.wrapping_add(words[i]))));

            state[4] = state[3];
            state[3] = state[2];
            state[2] = state[1].rotate_left(30);
            state[1] = state[0];
            state[0] = temp;
        }

        for i in 0..5 {
            self.state[i] = self.state[i].wrapping_add(state[i]);
        }
    }

    fn compute_padded(&mut self) {
        self.buffer.1[self.buffer.0] = 0x80;

        if self.buffer.0 > 55 {
            for i in self.buffer.0 + 1..64 {
                self.buffer.1[i] = 0;
            }

            self.compute();

            self.buffer.0 = 0;
        }

        for i in self.buffer.0 + 1..56 {
            self.buffer.1[i] = 0;
        }

        self.buffer.1[56..64].copy_from_slice(&(self.total * 8).to_be_bytes());

        self.compute();
    }
}

impl HashFn<64, 20> for Sha1 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::STATE,
            buffer: (0, [0u8; 64]),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u64;

        for i in 0..data.len() {
            self.buffer.1[self.buffer.0] = data[i];
            self.buffer.0 += 1;

            if self.buffer.0 == 64 {
                self.compute();
                self.buffer.0 = 0;
            }
        }
    }

    fn finalize(mut self) -> Hash<20> {
        self.compute_padded();

        let mut hash = [0u8; 20];

        for i in 0..5 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<20> {
        self.compute_padded();

        let mut hash = [0u8; 20];

        for i in 0..5 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::STATE;
        self.buffer = (0, [0u8; 64]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha1() {
        let hash = Sha1::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "943a702d06f34599aee1f8da8ef9f7296031d699"
        );
    }
}
