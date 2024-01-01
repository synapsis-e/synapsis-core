use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey};


pub struct Crypto;

impl Crypto {
    fn generate_keys() -> (SecretKey, secp256k1::PublicKey) {
        let secp = Secp256k1::new();

        secp.generate_keypair(&mut OsRng)
    }

    fn encrypt(text: &str) -> _ {

    }
}
