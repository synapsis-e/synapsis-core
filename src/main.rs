mod crypto;

use crypto::Crypto;

fn main() {
    let crypted = Crypto::encrypt("Hello, world!".as_bytes());

    if crypted.is_err() {
        println!("{:?}", crypted.err());
        return;
    }

    let crypted = crypted.unwrap();
    let decrypted = Crypto::decrypt(crypted.into());

    if decrypted.is_err() {
        println!("{:?}", decrypted.err());
        return;
    }

    println!("Encrypted: {:?}", String::from_utf8(decrypted.unwrap().0))
}
