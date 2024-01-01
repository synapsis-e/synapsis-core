mod sign;

use ecies::{decrypt, encrypt, utils::generate_keypair, PublicKey, SecretKey};

use self::sign::{Sign, Signed};

#[derive(Debug)]
pub struct Encrypted(Signed, Vec<u8>, [u8; 65], [u8; 32]);

pub struct Crypto {
    sign: Sign,
}

impl Crypto {
    pub fn new() -> Self {
        Self {
            sign: Sign::new(),
        }
    }

    pub fn encrypt(&self, text: &[u8]) -> Encrypted {
        let (secret, public) = generate_keypair();
        let (s_secret, s_public) = (secret.serialize(), public.serialize());
        let encrypted = encrypt(&s_public, text)
            .unwrap();

        let signed = self.sign.sign(text);

        Encrypted(signed, encrypted, s_public, s_secret)
    }
}