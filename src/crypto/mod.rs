use ecies::{decrypt, encrypt, utils::generate_keypair};

pub struct Encrypted(Vec<u8>, [u8; 65], [u8; 32]);

pub struct MessageKey(Vec<u8>, [u8; 32]);

pub struct Decrypted(pub Vec<u8>);

pub struct Crypto;

#[derive(Debug)]
pub enum CryptoError {
    InvalidSignature,
    InvalidKey,
    Encryption,
    Unreachable
}

impl MessageKey {
    pub fn from_raw(message: Vec<u8>, key: [u8; 32]) -> MessageKey {
        MessageKey(message, key)
    }
}

impl From<Encrypted> for MessageKey {
    fn from(value: Encrypted) -> Self {
        MessageKey(value.0, value.2)
    }
}

impl Crypto {
    pub fn encrypt(text: &[u8]) -> Result<Encrypted, CryptoError> {
        let (secret, public) = generate_keypair();
        let (crypto_secret, crypto_public) = (secret.serialize(), public.serialize());
        let encrypted = encrypt(&crypto_public, text).map_err(|_| CryptoError::Encryption)?;

        Ok(Encrypted(encrypted, crypto_public, crypto_secret))
    }

    pub fn decrypt(encrypted: MessageKey) -> Result<Decrypted, CryptoError> {
        let decrypted = decrypt(&encrypted.1, &encrypted.0);

        Ok(
            Decrypted(
                    decrypted.map_err(|err| match err {
                    ecies::SecpError::InvalidSignature => CryptoError::InvalidSignature,
                    ecies::SecpError::InvalidPublicKey => CryptoError::Unreachable,
                    ecies::SecpError::InvalidSecretKey => CryptoError::InvalidKey,
                    ecies::SecpError::InvalidRecoveryId => CryptoError::Unreachable,
                    ecies::SecpError::InvalidMessage => CryptoError::InvalidKey,
                    ecies::SecpError::InvalidInputLength => CryptoError::Unreachable,
                    ecies::SecpError::TweakOutOfRange => CryptoError::Unreachable,
                    ecies::SecpError::InvalidAffine => CryptoError::Unreachable,
                })?
            )
        )
    }
}
