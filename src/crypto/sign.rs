use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, All};
use secp256k1::hashes::sha256;
use secp256k1::ecdsa::Signature;

#[derive(Debug)]
pub struct Signed(
    Signature,
    PublicKey,
    SecretKey
);

pub struct Sign {
    secp: Secp256k1<All>,
}

impl Sign {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    pub fn sign(&self, text: &[u8])
        -> Signed
    {
        let (private_key, public_key) = self.secp.generate_keypair(&mut OsRng);
        let message = Message::from_hashed_data::<sha256::Hash>(
            text
        );
        let signature = self.secp.sign_ecdsa(&message, &private_key);

        Signed(signature, public_key, private_key)
    }
}
