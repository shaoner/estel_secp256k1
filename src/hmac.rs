use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};
use std::convert::TryInto;

type HmacSha256 = Hmac<Sha256>;

/// sha256 digest x2
pub fn hash256(msg: &[u8]) -> [u8; 32] {
    let d1 = Sha256::digest(msg);

    Sha256::digest(&d1)
        .as_slice()
        .try_into()
        .expect("digest should be 32 bytes")
}

/// hash buffer with secret key k
pub fn hmac256(k: &[u8; 32], buf: &[u8]) -> [u8; 32] {
    let mut hm = HmacSha256::new_from_slice(k).unwrap();
    hm.update(buf);

    hm.finalize()
        .into_bytes()
        .try_into()
        .expect("hmac should be 32 bytes")
}
