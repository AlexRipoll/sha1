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

    pub fn hash(&mut self, key: &str) -> [u8; 20] {
        let (mut h0, mut h1, mut h2, mut h3, mut h4) = (H0, H1, H2, H3, H4);

        let msg = self.pad_message(key);

        for chunk in msg.chunks(64) {}
        [0; 20]
    }

    fn pad_message(&mut self, message: &str) -> Vec<u8> {
        let mut bytes = message.as_bytes().to_vec();
        let bit_length: u64 = bytes.len().saturating_mul(8) as u64;

        // Append the '1' at the most most significant bit: 10000000 (0x80)
        bytes.push(0x80);

        while bytes.len().saturating_mul(8) % 512 != 448 {
            bytes.push(0);
        }

        bytes.extend_from_slice(&bit_length.to_be_bytes());

        bytes
    }

    /// Builds W sequence array from a 512-bit chunk.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc3174#section-6.1 a and b
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
