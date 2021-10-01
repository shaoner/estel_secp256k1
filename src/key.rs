use crate::ecc::{G, Pt};
use crate::scalar::Scalar;
use crate::hmac::{hash256, hmac256};

/// ECDSA signature
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

impl Signature {
    /// Serialize a signature using the DER format
    /// This is compatible with OpenSSL standards and most crypto software
    pub fn serialize_der(&self) -> ([u8; 72], usize) {
        // copy bytes from n to res and returns length of n
        // der format requires an additional 0 if the first bit is 1
        fn copy_scalar(n: &Scalar, res: &mut [u8]) -> usize {
            let nbin = n.to_bytes();

            let mut i = 0;
            while i < 31 && nbin[i] == 0 && nbin[i + 1] < 0x80 {
                i += 1;
            }
            let len = 32 - i;
            if nbin[i] != 0 {
                res[0] = 0;
                res[1..(1 + len)].copy_from_slice(&nbin[i..32]);
                len + 1
            } else {
                res[0..len].copy_from_slice(&nbin[i..32]);
                len
            }
        }
        let mut res = [0u8; 72];
        res[0] = 0x30;
        res[2] = 0x02;
        let rlen = copy_scalar(&self.r, &mut res[4..37]);
        res[3] = rlen as u8;
        res[4 + rlen] = 0x02;
        let slen = copy_scalar(&self.s, &mut res[(6 + rlen)..(39 + rlen)]);
        res[5 + rlen] = slen as u8;
        let len = slen + rlen + 4;
        res[1] = len as u8;

        (res, len + 2)
    }
}

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
pub struct PublicKey {
    key: Pt
}

impl PublicKey {
    /// Create a public key from a secret
    pub fn from_secret(secret: &Scalar) -> Self {
        Self { key: G * secret }
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
    fn it_serializes_signature() {
        let sig = Signature {
            r: Scalar::new(
                0xe45a150a8eafef6f,
                0x5a3dfef6d3728674,
                0x92eb9d31e3ffb254,
                0x013767c71e093276
            ),
            s: Scalar::new(
                0xb73a3f6c5b200750,
                0x4a36806a5f7f4ff9,
                0xfac211cc4a842a2e,
                0x906562f286a46255,
            ),
        };

        let sigbin = sig.serialize_der();

        let exp = [
            0x30, 0x46, 0x02, 0x21, 0x00, 0xe4, 0x5a, 0x15, 0x0a, 0x8e, 0xaf, 0xef, 0x6f, 0x5a,
            0x3d, 0xfe, 0xf6, 0xd3, 0x72, 0x86, 0x74, 0x92, 0xeb, 0x9d, 0x31, 0xe3, 0xff, 0xb2,
            0x54, 0x01, 0x37, 0x67, 0xc7, 0x1e, 0x09, 0x32, 0x76, 0x02, 0x21, 0x00, 0xb7, 0x3a,
            0x3f, 0x6c, 0x5b, 0x20, 0x07, 0x50, 0x4a, 0x36, 0x80, 0x6a, 0x5f, 0x7f, 0x4f, 0xf9,
            0xfa, 0xc2, 0x11, 0xcc, 0x4a, 0x84, 0x2a, 0x2e, 0x90, 0x65, 0x62, 0xf2, 0x86, 0xa4,
            0x62, 0x55,
        ];
        assert_eq!(sigbin, exp);
    }
}
