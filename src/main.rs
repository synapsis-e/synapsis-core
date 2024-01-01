mod crypto;

use crypto::Crypto;

fn main() {
    let crypto = Crypto::new();
    println!("{:?}", crypto.encrypt("Hello, world!".as_bytes()));
}
