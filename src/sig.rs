use crate::error::Error;
use crate::scalar::Scalar;

/// ECDSA signature
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    pub fn parse_der(bin: &[u8]) -> Result<Self, Error> {
        fn parse_scalar(bin: &[u8], len: usize) -> Result<Scalar, Error> {
            let mut b = [0u8; 32];
            let start = if bin[0] == 0x0 { 1 } else { 0 };
            if len > (32 + start) {
                return Err(Error::InvalidBuffer);
            }
            b[(32 + start - len)..32].copy_from_slice(&bin[start..len]);

            Ok(Scalar::from_bytes(&b))
        }
        if bin.len() < 6 {
            return Err(Error::InvalidBuffer);
        }
        let tlen = bin[1] as usize;
        if bin.len() != (tlen + 2) || bin[0] != 0x30 || bin[2] != 0x02 {
            return Err(Error::InvalidBuffer);
        }
        let rlen = bin[3] as usize;
        if bin.len() < (rlen + 6) {
            return Err(Error::InvalidBuffer);
        }
        let r = parse_scalar(&bin[4..(4 + rlen)], rlen)?;
        if bin[4 + rlen] != 0x02 {
            return Err(Error::InvalidBuffer);
        }
        let slen = bin[5 + rlen] as usize;
        if (rlen + slen + 4) != tlen {
            return Err(Error::InvalidBuffer);
        }
        let s = parse_scalar(&bin[(6 + rlen)..(6 + rlen + slen)], slen)?;

        Ok(Signature { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let (bin, _) = sig.serialize_der();

        let exp = [
            0x30, 0x46, 0x02, 0x21, 0x00, 0xe4, 0x5a, 0x15, 0x0a, 0x8e, 0xaf, 0xef, 0x6f, 0x5a,
            0x3d, 0xfe, 0xf6, 0xd3, 0x72, 0x86, 0x74, 0x92, 0xeb, 0x9d, 0x31, 0xe3, 0xff, 0xb2,
            0x54, 0x01, 0x37, 0x67, 0xc7, 0x1e, 0x09, 0x32, 0x76, 0x02, 0x21, 0x00, 0xb7, 0x3a,
            0x3f, 0x6c, 0x5b, 0x20, 0x07, 0x50, 0x4a, 0x36, 0x80, 0x6a, 0x5f, 0x7f, 0x4f, 0xf9,
            0xfa, 0xc2, 0x11, 0xcc, 0x4a, 0x84, 0x2a, 0x2e, 0x90, 0x65, 0x62, 0xf2, 0x86, 0xa4,
            0x62, 0x55,
        ];
        assert_eq!(bin, exp);
    }

    #[test]
    fn it_parses_serialized_signature() {
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

        let (bin, len) = sig.serialize_der();
        let exp = Signature::parse_der(&bin[..len]).unwrap();

        assert_eq!(exp, sig);
    }

    #[test]
    fn it_cannot_parse_signature() {
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

        let (bin, len) = sig.serialize_der();
        let exp = Signature::parse_der(&bin[1..len]).unwrap_err();
        assert_eq!(exp, Error::InvalidBuffer);

        let exp = Signature::parse_der(&bin[0..10]).unwrap_err();
        assert_eq!(exp, Error::InvalidBuffer);

        let bin = [0u8; 72];
        let exp = Signature::parse_der(&bin[0..72]).unwrap_err();
        assert_eq!(exp, Error::InvalidBuffer);
    }
}
