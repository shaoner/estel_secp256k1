mod ecc;
mod error;
mod field;
mod hmac;
mod key;
mod scalar;
mod sig;

pub use crate::error::Error;
pub use crate::hmac::hash256;
pub use crate::key::{PrivateKey, PublicKey};
pub use crate::scalar::Scalar;
pub use crate::sig::Signature;

/// Create a keypair from a buffer seed
///
/// Given that a secret is used to generate both a PrivateKey and a Public key,
/// this create both at once as a wrapper
///
/// # Example
///
/// ```
/// use estel_secp256k1::generate_keypair_from_seed;
///
/// let (privkey, pubkey) = generate_keypair_from_seed("some password".as_bytes());
/// ```
pub fn generate_keypair_from_seed(seed: &[u8]) -> (PrivateKey, PublicKey) {
    let secret = Scalar::from_bytes(&hash256(seed));
    let pk = PublicKey::from_secret(&secret);
    let pvk = PrivateKey::new(secret);

    (pvk, pk)
}
