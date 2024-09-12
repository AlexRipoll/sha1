pub struct Sha1;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

impl Sha1 {
    pub fn new() -> Self {
        Self
    }

    pub fn digest(&mut self, key: &str) -> [u8; 20] {
        let (mut h0, mut h1, mut h2, mut h3, mut h4) = (H0, H1, H2, H3, H4);

        let msg = self.pad_message(key);

        for chunk in msg.chunks(64) {
            let w = self.build_w_sequence(chunk);
            let (mut a, mut b, mut c, mut d, mut e) = (H0, H1, H2, H3, H4);

            for i in 0..80 {
                // https://datatracker.ietf.org/doc/html/rfc3174#section-5
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };

                // https://datatracker.ietf.org/doc/html/rfc3174#section-6.1 (d)
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(w[i])
                    .wrapping_add(k);

                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            // Add the compressed chunk to the current hash value.
            // https://datatracker.ietf.org/doc/html/rfc3174#section-6.1 (e)
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        let mut digest = [0u8; 20];

        digest[0..4].copy_from_slice(&h0.to_be_bytes());
        digest[4..8].copy_from_slice(&h1.to_be_bytes());
        digest[8..12].copy_from_slice(&h2.to_be_bytes());
        digest[12..16].copy_from_slice(&h3.to_be_bytes());
        digest[16..20].copy_from_slice(&h4.to_be_bytes());

        digest
    }

    fn pad_message(&mut self, message: &str) -> Vec<u8> {
        let mut bytes = message.as_bytes().to_vec();
        let bit_length: u64 = bytes.len().wrapping_mul(8) as u64;

        // Append the '1' at the most most significant bit: 10000000 (0x80)
        bytes.push(0x80);

        while bytes.len().saturating_mul(8) % 512 != 448 {
            bytes.push(0);
        }

        bytes.extend_from_slice(&bit_length.to_be_bytes());

        bytes
    }

    /// Builds W sequence array from a 512-bit chunk.
    //
    // https://datatracker.ietf.org/doc/html/rfc3174#section-6.1 (a) and (b)
    fn build_w_sequence(&mut self, chunk: &[u8]) -> [u32; 80] {
        let mut w = [0u32; 80];

        // Initialize the first 16 words in the array from the chunk.
        for (i, block) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes(block.try_into().unwrap());
        }

        // Extend the schedule array using previously defined values and XOR (^) operations.
        for i in 16..80 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = w[i].rotate_left(1);
        }

        w
    }
}
