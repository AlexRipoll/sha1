use sha1::Sha1;

mod sha1;

fn main() {
    let mut sha1 = Sha1::new();
    let hex: String = sha1
        .digest("hello world")
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("{}", hex);
}
