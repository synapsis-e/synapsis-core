use crate::crypto::Crypto;

mod crypto;

fn main() {
    println!("{:?}", Crypto::generate_keys());
}
