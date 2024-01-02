use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, All, ecdsa};
use secp256k1::hashes::sha256;
use secp256k1::ecdsa::Signature;

#[derive(Debug)]
pub struct Signed(
    Signature,
    PublicKey,
    SecretKey
);

#[derive(Debug)]
pub enum SignError {
    InvalidMessage,
    InvalidPublicKey,
    InvalidSignature,
    IncorrectSignature,
    
}

pub struct Sign;

impl Sign {
    pub fn sign(&self, text: &[u8])
        -> Signed
    {
        let secp = Secp256k1::signing_only();
        let (private_key, public_key) = self.secp.generate_keypair(&mut OsRng);
        let message = Message::from_hashed_data::<sha256::Hash>(
            text
        );
        let signature = self.secp.sign_ecdsa(&message, &private_key);

        Signed(signature, public_key, private_key)
    }

    pub fn verify(&self, text: &[u8], signature: &[u8], public: &[u8]) -> _ {
        let secp = Secp256k1::verification_only();
        let message = Message::from_digest_slice(text).map_err(|_| SignError::InvalidMessage)?;
        let public_key = PublicKey::from_slice(public).map_err(|_| SignError::InvalidPublicKey)?;
        let signature = ecdsa::Signature::from_compact(signature).map_err(|_| SignError::InvalidSignature)?;

        secp.verify_ecdsa(&message, &signature, &public_key)
            .map_err(|err| match err {
                secp256k1::Error::IncorrectSignature => SignError::IncorrectSignature,
                secp256k1::Error::InvalidMessage => SignError::InvalidMessage,
                secp256k1::Error::InvalidPublicKey => SignError::InvalidPublicKey,
                secp256k1::Error::InvalidSignature => SignError::InvalidSignature,
                secp256k1::Error::InvalidSecretKey => todo!(),
                secp256k1::Error::InvalidSharedSecret => todo!(),
                secp256k1::Error::InvalidRecoveryId => todo!(),
                secp256k1::Error::InvalidTweak => todo!(),
                secp256k1::Error::NotEnoughMemory => todo!(),
                secp256k1::Error::InvalidPublicKeySum => todo!(),
                secp256k1::Error::InvalidParityValue(_) => todo!(),
                secp256k1::Error::InvalidEllSwift => todo!(),
            })
    }
}
