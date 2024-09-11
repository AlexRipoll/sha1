pub struct Sha1;

impl Sha1 {
    pub fn new() -> Self {
        Self
    }

    pub fn hash(&mut self, key: &str) -> [u8; 20] {
        let msg = self.pad_message(key);
        println!("{:?}", msg);

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
}
