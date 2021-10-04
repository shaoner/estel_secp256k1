use std::convert::TryInto;

use crate::ecc::{G, Pt, SECP256K1_B};
use crate::error::Error;
use crate::field::El;
use crate::hmac::{hash256, hmac256};
use crate::scalar::Scalar;
use crate::sig::Signature;

/// Represent a private key including a secret
pub struct PrivateKey {
    secret: Scalar,
}

impl PrivateKey {
    /// Create a new PrivateKey from a secret number
    ///
    /// This is useful is you already have a hash of a password and want to
    /// create both a private key and a public key.
    ///
    /// # Example
    ///
    /// ```
    /// use estel_secp256k1::*;
    ///
    /// let password = "the force".as_bytes();
    /// let secret = Scalar::from_bytes(&hash256(&password));
    /// let pk = PrivateKey::new(secret);
    /// ```
    pub fn new(secret: Scalar) -> Self {
        Self { secret }
    }

    fn calculate_k(&self, z: &Scalar) -> Scalar {
        let zbytes = z.to_bytes();
        let secbytes = self.secret.to_bytes();
        let mut v = [0x01; 32];
        let mut k = [0x00; 32];
        let mut tmp = [0x01; 97]; // v[32] + secret[32] + z[32] + 1
        let n_1 = Scalar::from_u64(1);

        // tmp[0..32] = 1
        tmp[32] = 0u8;
        tmp[33..65].copy_from_slice(&secbytes[..]);
        tmp[65..97].copy_from_slice(&zbytes[..]);

        // K = HMAC_K(V || 0x00 || secret || z)
        k = hmac256(&k, &tmp);
        // V = HMAC_K(V)
        v = hmac256(&k, &v);

        tmp[0..32].copy_from_slice(&v);
        tmp[32] = 1u8;

        // K = HMAC_K(V || 0x01 || secret || z)
        k = hmac256(&k, &tmp);
        // V = HMAC_K(V)
        v = hmac256(&k, &v);

        tmp[32] = 0u8;

        loop {
            // V = HMAC_K(V)
            v = hmac256(&k, &v);

            let res = Scalar::from_bytes(&v);
            if res >= n_1 && res.get_overflow() == 0 {
                return res;
            }

            // K = HMAC_K(V || 0x00)
            tmp[0..32].copy_from_slice(&v);
            k = hmac256(&k, &tmp[0..32]);
            // V = HMAC_K(V)
            v = hmac256(&k, &v);
        }
    }

    /// Create a signature from a hash
    ///
    /// The signature can then be used to verify that:
    /// 1/ the hash wasn't tampered
    /// 2/ the signature belongs to the associated public key
    ///
    /// # Example
    ///
    /// ```
    /// use estel_secp256k1::*;
    ///
    /// let secret = Scalar::from_bytes(&hash256("the force".as_bytes()));
    /// let pk = PrivateKey::new(secret);
    /// let msg = "The greatest teacher failure is".as_bytes();
    /// let hash = Scalar::from_bytes(&hash256(&msg));
    /// let sig = pk.sign(&hash);
    /// ```
    pub fn sign(&self, z: &Scalar) -> Signature {
        let mut k = self.calculate_k(z);
        let r = G * &k;
        let rx = r.x.to_scalar();

        k.modinv_inner();

        // s = ((z + rx * secret) / k) % N
        let s = (*z + rx.mulmod(&self.secret)).mulmod(&k);

        Signature { r: rx, s }
    }

    /// Create a signature from a buffer
    ///
    /// The signature can then be used to verify that:
    /// 1/ the msg (buffer) was not tampered
    /// 2/ the signature belongs to the associated public key
    ///
    /// # Example
    ///
    /// ```
    /// use estel_secp256k1::*;
    ///
    /// let secret = Scalar::from_bytes(&hash256("the force".as_bytes()));
    /// let pk = PrivateKey::new(secret);
    /// let msg = "The greatest teacher failure is".as_bytes();
    /// let sig = pk.sign_buffer(&msg);
    /// ```
    pub fn sign_buffer(&self, buf: &[u8]) -> Signature {
        let hash = hash256(buf);
        let z = Scalar::from_bytes(&hash);

        self.sign(&z)
    }
}

/// Represent a public key containing an ECC point
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey {
    key: Pt
}

impl PublicKey {
    /// Create a public key from a secret
    pub fn from_secret(secret: &Scalar) -> Self {
        Self { key: G * secret }
    }

    /// Create a public key from ECC coordinates x and y
    pub const fn from_coords(x: El, y: El) -> Self {
        Self { key: Pt::new(x, y) }
    }

    /// Verify that a signature is valid for a given hash
    ///
    /// This validates that a signature was generated from the same secret used
    /// for the public key.
    /// It's also possible to use [`verify`] if you calculate the hash.
    pub fn verify(&self, z: &Scalar, sig: &Signature) -> bool {
        let mut s_inv = sig.s;

        s_inv.modinv_inner();

        let u = z.mulmod(&s_inv);
        let v = sig.r.mulmod(&s_inv);
        let r = G * &u + self.key * &v;

        sig.r == r.x.to_scalar()
    }

    /// Verify that a signature is valid for a given buffer
    ///
    /// This validates that a signature was generated from the same secret used
    /// for the public key.
    /// It's also possible to use [`verify`] if you calculate the hash.
    pub fn verify_buffer(&self, buf: &[u8], sig: &Signature) -> bool {
        let hash = hash256(buf);
        let z = Scalar::from_bytes(&hash);

        self.verify(&z, sig)
    }

    pub fn serialize_sec_uncompressed(&mut self) -> [u8; 65] {
        let mut key = self.key;
        assert!(!key.inf);

        key.y.reduce();
        key.x.reduce();

        let mut res = [0u8; 65];
        let xb = key.x.to_bytes();
        let yb = key.y.to_bytes();

        res[0] = 0x04;
        res[1..33].copy_from_slice(&xb);
        res[33..65].copy_from_slice(&yb);

        res
    }

    pub fn serialize_sec_compressed(&mut self) -> [u8; 33] {
        let mut key = self.key;

        assert!(!key.inf);
        key.y.reduce();
        key.x.reduce();

        let mut res = [0u8; 33];
        let x = key.x.to_bytes();

        res[0] = if key.y.is_even() { 0x02u8 } else { 0x03u8 };
        res[1..33].copy_from_slice(&x);

        res
    }

    pub fn parse_sec(bin: &[u8]) -> Result<Self, Error> {
        let xbin: [u8; 32] = bin[1..33].try_into().or(Err(Error::InvalidBuffer))?;

        if bin[0] == 0x04 {
            // uncompressed
            let ybin: [u8; 32] = bin[33..65].try_into().or(Err(Error::InvalidBuffer))?;

            let x = El::from_bytes(&xbin);
            let y = El::from_bytes(&ybin);

            Ok(Self::from_coords(x, y))
        } else {
            // compressed
            // y^2 = x^3 + 7
            // -> y_1 = (x^3 + 7).sqrt()
            // -> y_2 = P - y_1
            let is_even = bin[0] == 0x02;

            let x = El::from_bytes(&xbin);
            let x3 = x.square() * x;
            let y2 = x3 + El::from_u64(SECP256K1_B);
            let (_y, is_valid) = y2.sqrt();

            if !is_valid {
                return Err(Error::InvalidBuffer);
            }

            if _y.is_even() {
                if is_even {
                    Ok(Self::from_coords(x, _y))
                } else {
                    Ok(Self::from_coords(x, _y.negate(1)))
                }
            } else {
                if is_even {
                    Ok(Self::from_coords(x, _y.negate(1)))
                } else {
                    Ok(Self::from_coords(x, _y))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_tests_k_is_deterministic() {
        let msg = "Hello World";
        let password = "n00b";
        let m = hash256(msg.as_bytes());
        let p = hash256(password.as_bytes());

        let z = Scalar::from_bytes(&m);
        let e = Scalar::from_bytes(&p);

        let pvk = PrivateKey::new(e);

        let k = pvk.calculate_k(&z);

        assert_eq!(k, Scalar::new(0xc48006ba13d01330,
                                  0xe9aebcbeb107b26c,
                                  0x99e8f7edbfd876c1,
                                  0xe940b9e3cd5637f7));
    }

    #[test]
    fn it_checks_public_key_serialization() {
        let mut p = PublicKey::from_coords(
            El::new(0x8b4b5f165df3c2be,
                    0x8c6244b5b7456388,
                    0x43e4a781a15bcd1b,
                    0x69f79a55dffdf80c),
            El::new(0x4aad0a6f68d308b4,
                    0xb3fbd7813ab0da04,
                    0xf9e336546162ee56,
                    0xb3eff0c65fd4fd36)
        );

        let sec_compressed = p.serialize_sec_compressed();
        let sec_uncompressed = p.serialize_sec_uncompressed();

        let p1 = PublicKey::parse_sec(&sec_uncompressed).unwrap();
        let p2 = PublicKey::parse_sec(&sec_compressed).unwrap();

        assert_eq!(p, p1);
        assert_eq!(p, p2);
    }
}
