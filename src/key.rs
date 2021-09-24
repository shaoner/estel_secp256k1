use crate::ecc::{G, N, Pt};
use crate::scalar::Scalar;
use crate::hmac::{hash256, hmac256};

pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

pub struct PrivateKey {
    secret: Scalar,
}

impl PrivateKey {
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
            if res >= n_1 && res < N {
                return res;
            }

            // K = HMAC_K(V || 0x00)
            tmp[0..32].copy_from_slice(&v);
            k = hmac256(&k, &tmp[0..32]);
            // V = HMAC_K(V)
            v = hmac256(&k, &v);
        }
    }

    pub fn sign(&self, z: &Scalar) -> Signature {
        let mut k = self.calculate_k(z);
        let r = G * &k;
        let rx = r.x.to_scalar();

        k.modinv_inner(&N);

        // s = ((z + rx * secret) / k) % N
        let s = (*z + rx.mulmod(&self.secret)).mulmod(&k);

        Signature { r: rx, s }
    }

    pub fn sign_from_buffer(&self, buf: &[u8]) -> Signature {
        let hash = hash256(buf);
        let z = Scalar::from_bytes(&hash);

        self.sign(&z)
    }
}

pub struct PublicKey {
    key: Pt
}

impl PublicKey {
    pub fn from_secret(secret: &Scalar) -> Self {
        Self { key: G * &secret }
    }

    pub fn verify(&self, z: &Scalar, sig: &Signature) -> bool {
        let mut s_inv = sig.s;

        s_inv.modinv_inner(&N);

        let u = z.mulmod(&s_inv);
        let v = sig.r.mulmod(&s_inv);
        let r = G * &u + self.key * &v;

        sig.r == r.x.to_scalar()
    }

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
    fn it_creates_a_signature() {
        let msg = "Hello World";
        let password = "n00b";
        let m = hash256(msg.as_bytes());
        let p = hash256(password.as_bytes());

        let z = Scalar::from_bytes(&m);
        let e = Scalar::from_bytes(&p);

        let pvk = PrivateKey::new(e);
        let sig = pvk.sign(&z);
        let pubk = PublicKey::from_secret(&e);

        assert!(pubk.verify(&z, &sig));
    }
}
