use std::cmp::Ordering;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

#[cfg(debug_assertions)]
use std::fmt;

use crate::scalar::Scalar;

const P: Scalar = Scalar::new(0xffffffffffffffff,
                              0xffffffffffffffff,
                              0xffffffffffffffff,
                              0xfffffffefffffc2f);

/// Represent a Field Element with P = 2^256 - 2^32 - 977
#[derive(Clone, Copy, Eq)]
pub struct El {
    d: [u64; 5]
}

impl El {
    pub const fn new(d3: u64, d2: u64, d1: u64, d0: u64) -> Self {
        let (t0, t1, t2, t3): (u64, u64, u64, u64);
        let t4: u64;

        t0 = d0 & 0x000fffffffffffff;
        t1 = d0 >> 52 | (d1 & 0x000000ffffffffff) << 12; // 12 + 40
        t2 = d1 >> 40 | (d2 & 0x000000000fffffff) << 24; // 24 + 28
        t3 = d2 >> 28 | (d3 & 0x000000000000ffff) << 36; // 36 + 16
        t4 = d3 >> 16; // 48

        Self { d: [t0, t1, t2, t3, t4] }
    }

    pub const fn from_u64(n: u64) -> Self {
        Self::new(0, 0, 0, n)
    }

    pub fn is_zero(&self) -> bool {
        self.d[0] | self.d[1] | self.d[2] | self.d[3] | self.d[4] == 0
    }

    pub fn is_even(&self) -> bool {
        self.d[0] & 0x1 == 0
    }

    /// Convert a field element to a scalar
    pub fn to_scalar(&self) -> Scalar {
        let d0 = (self.d[0] >> 0) | (self.d[1] << 52);
        let d1 = (self.d[1] >> 12) | (self.d[2] << 40);
        let d2 = (self.d[2] >> 24) | (self.d[3] << 28);
        let d3 = (self.d[3] >> 36) | (self.d[4] << 16);

        Scalar::new(d3, d2, d1, d0)
    }

    /// Assign a scalar to the current field element
    pub fn from_scalar(&mut self, n: &Scalar) {
        let d0 = n.d[0] & 0x000fffffffffffff;
        let d1 = n.d[0] >> 52 | (n.d[1] & 0x000000ffffffffff) << 12;
        let d2 = n.d[1] >> 40 | (n.d[2] & 0x000000000fffffff) << 24;
        let d3 = n.d[2] >> 28 | (n.d[3] & 0x000000000000ffff) << 36;
        let d4 = n.d[3] >> 16;

        self.d = [d0, d1, d2, d3, d4];
    }

    /// Convert a field element to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];

        b[31] = self.d[0] as u8;
        b[30] = (self.d[0] >> 8) as u8;
        b[29] = (self.d[0] >> 16) as u8;
        b[28] = (self.d[0] >> 24) as u8;
        b[27] = (self.d[0] >> 32) as u8;
        b[26] = (self.d[0] >> 40) as u8;
        b[25] = (self.d[0] >> 48) as u8 | (self.d[1] << 4) as u8;

        b[24] = (self.d[1] >> 4) as u8;
        b[23] = (self.d[1] >> 12) as u8;
        b[22] = (self.d[1] >> 20) as u8;
        b[21] = (self.d[1] >> 28) as u8;
        b[20] = (self.d[1] >> 36) as u8;
        b[19] = (self.d[1] >> 44) as u8;

        b[18] = self.d[2] as u8;
        b[17] = (self.d[2] >> 8) as u8;
        b[16] = (self.d[2] >> 16) as u8;
        b[15] = (self.d[2] >> 24) as u8;
        b[14] = (self.d[2] >> 32) as u8;
        b[13] = (self.d[2] >> 40) as u8;
        b[12] = (self.d[2] >> 48) as u8 | (self.d[3] << 4) as u8;

        b[11] = (self.d[3] >> 4) as u8;
        b[10] = (self.d[3] >> 12) as u8;
        b[9] = (self.d[3] >> 20) as u8;
        b[8] = (self.d[3] >> 28) as u8;
        b[7] = (self.d[3] >> 36) as u8;
        b[6] = (self.d[3] >> 44) as u8;

        b[5] = self.d[4] as u8;
        b[4] = (self.d[4] >> 8) as u8;
        b[3] = (self.d[4] >> 16) as u8;
        b[2] = (self.d[4] >> 24) as u8;
        b[1] = (self.d[4] >> 32) as u8;
        b[0] = (self.d[4] >> 40) as u8;

        b
    }

    /// Multiply a field element with a small unsigned int
    pub fn mul_scalar_assign(&mut self, n: u64) {
        debug_assert!(n < 0x1000);

        self.d[0] *= n;
        self.d[1] *= n;
        self.d[2] *= n;
        self.d[3] *= n;
        self.d[4] *= n;
    }

    /// Multiply 2 field elements
    pub fn mul_fe_assign(&mut self, b: &Self) {
        const M52: u128 = 0x000fffffffffffffu128; // 2^52 - 1
        const M48: u64 = 0x0000ffffffffffffu64; // 2^48 - 1
        const P0: u128 = 0x1000003d1u128; // 2^32 + 977
        const P1: u128 = 0x1000003d10u128; // 2^32 + 977 << 4

        let (a0, a1, a2, a3, a4) = (
            self.d[0] as u128, self.d[1] as u128, self.d[2] as u128,
            self.d[3] as u128, self.d[4] as u128
        );
        let (b0, b1, b2, b3, b4) = (
            b.d[0] as u128, b.d[1] as u128, b.d[2] as u128,
            b.d[3] as u128, b.d[4] as u128
        );
        let mut tx: u128;
        let mut cx: u128;
        let (t0, t1, t2, mut t3, mut t4, mut t5): (u64, u64, u64, u64, u64, u128);
        let c4: u64;

        // t3
        tx = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
        // t8
        cx = a4 * b4;
        tx += (cx & M52) * P1;
        cx >>= 52;
        t3 = (tx & M52) as u64;
        tx >>= 52;

        // t4
        tx += a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        tx += cx * P1;
        t4 = (tx & M52) as u64;
        tx >>= 52;
        c4 = t4 >> 48;
        t4 &= M48;

        // t5
        cx = tx + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
        // t0
        tx = a0 * b0;
        t5 = cx & M52;
        cx >>= 52;
        t5 = (t5 << 4) | c4 as u128;
        tx += t5 * P0;
        t0 = (tx & M52) as u64;
        tx >>= 52;

        // t1
        tx += a0 * b1 + a1 * b0;
        // t6
        cx += a2 * b4 + a3 * b3 + a4 * b2;
        tx += (cx & M52) * P1;
        cx >>= 52;
        t1 = (tx & M52) as u64;
        tx >>= 52;

        // t2
        tx += a0 * b2 + a1 * b1 + a2 * b0;
        // t07
        cx += a3 * b4 + a4 * b3;
        // t12
        tx += (cx & M52) * P1;
        cx >>= 52;
        t2 = (tx & M52) as u64;
        tx >>= 52;

        // t23
        tx += cx * P1 + t3 as u128;
        t3 = (tx & M52) as u64;
        tx >>= 52;
        // t24
        tx += t4 as u128;
        t4 = tx as u64;

        self.d = [t0, t1, t2, t3, t4];
    }

    /// Calculate the a field element square (optimized multiplication)
    pub fn square(&mut self) {
        const M52: u128 = 0x000fffffffffffffu128; // 2^52 - 1
        const M48: u64 = 0x0000ffffffffffffu64; // 2^48 - 1
        const P0: u128 = 0x1000003d1u128; // 2^32 + 977
        const P1: u128 = 0x1000003d10u128; // 2^32 + 977 << 4

        let (a0, a1, a2, a3, a4) = (
            self.d[0] as u128, self.d[1] as u128, self.d[2] as u128,
            self.d[3] as u128, self.d[4] as u128
        );
        let mut tx: u128;
        let mut cx: u128;
        let (t0, t1, t2, mut t3, mut t4, mut t5): (u64, u64, u64, u64, u64, u128);
        let c4: u64;

        // t3
        tx = a0 * a3 * 2 + a1 * a2 * 2;
        // t8
        cx = a4 * a4;
        tx += (cx & M52) * P1;
        cx >>= 52;
        t3 = (tx & M52) as u64;
        tx >>= 52;

        // t4
        tx += a0 * a4 * 2 + a1 * a3 * 2 + a2 * a2;
        tx += cx * P1;
        t4 = (tx & M52) as u64;
        tx >>= 52;
        c4 = t4 >> 48;
        t4 &= M48;

        // t5
        cx = tx + a1 * a4 * 2 + a2 * a3 * 2;
        // t0
        tx = a0 * a0;
        t5 = cx & M52;
        cx >>= 52;
        t5 = (t5 << 4) | c4 as u128;
        tx += t5 * P0;
        t0 = (tx & M52) as u64;
        tx >>= 52;

        // t1
        tx += a0 * a1 * 2;
        // t6
        cx += a2 * a4 * 2 + a3 * a3;
        tx += (cx & M52) * P1;
        cx >>= 52;
        t1 = (tx & M52) as u64;
        tx >>= 52;

        // t2
        tx += a0 * a2 * 2 + a1 * a1;
        // t07
        cx += a3 * a4 * 2;
        // t12
        tx += (cx & M52) * P1;
        cx >>= 52;
        t2 = (tx & M52) as u64;
        tx >>= 52;

        // t23
        tx += cx * P1 + t3 as u128;
        t3 = (tx & M52) as u64;
        tx >>= 52;
        // t24
        tx += t4 as u128;
        t4 = tx as u64;

        self.d = [t0, t1, t2, t3, t4];
    }

    /// Calculate the inverse of the field element
    /// use a modular inverse with binary gcd
    pub fn inverse(&mut self) {
        self.reduce();
        let mut n = self.to_scalar();
        n.modinv_inner_from(&P);
        self.from_scalar(&n);
    }

    /// Reduce the field element by removing the carries
    pub fn reduce(&mut self) {
        const M52: u64 = 0x000fffffffffffffu64;
        const M48: u64 = 0x0000ffffffffffffu64;
        const P0: u64 = 0x1000003d1u64;
        let (mut d0, mut d1, mut d2, mut d3, mut d4) = (self.d[0], self.d[1], self.d[2], self.d[3], self.d[4]);
        let mut c: u64;

        c = d4 >> 48;

        d4 &= M48;
        d0 += c * P0;
        d1 += d0 >> 52;
        d0 &= M52;
        d2 += d1 >> 52;
        d1 &= M52;
        d3 += d2 >> 52;
        d2 &= M52;
        d4 += d3 >> 52;
        d3 &= M52;

        // n >= P
        if d4 > M48 || (d4 == M48 && (d3 & d2 & d1) == M52 && d0 >= 0xffffefffffc2f) {
            if d4 > M48 {
                c = d4 >> 48;
            } else {
                c = 1
            }
            d4 &= M48;
            d0 += c * P0;
            d1 += d0 >> 52;
            d0 &= M52;
            d2 += d1 >> 52;
            d1 &= M52;
            d3 += d2 >> 52;
            d2 &= M52;
            d4 += d3 >> 52;
            d3 &= M52;
            d4 &= M48
        }

        self.d = [d0, d1, d2, d3, d4];
    }
}

#[cfg(debug_assertions)]
impl fmt::Debug for El {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:012x}{:013x}{:013x}{:013x}{:013x}",
               self.d[4], self.d[3], self.d[2], self.d[1], self.d[0])
    }
}

impl Default for El {
    fn default() -> El {
        Self { d: [0u64; 5] }
    }
}

impl Add<El> for El {
    type Output = El;

    fn add(self, rhs: El) -> El {
        let mut r = self;

        r.add_assign(&rhs);
        r
    }
}

impl<'a, 'b> Add<&'a El> for &'b El {
    type Output = El;

    fn add(self, rhs: &'a El) -> El {
        let mut r = *self;

        r.add_assign(rhs);
        r
    }
}

impl<'a> AddAssign<&'a El> for El {
    fn add_assign(&mut self, rhs: &'a El) {
        self.d[0] += rhs.d[0];
        self.d[1] += rhs.d[1];
        self.d[2] += rhs.d[2];
        self.d[3] += rhs.d[3];
        self.d[4] += rhs.d[4];
    }
}

impl AddAssign<El> for El {
    fn add_assign(&mut self, rhs: El) {
        self.add_assign(&rhs)
    }
}

impl Mul<u64> for El {
    type Output = El;

    fn mul(self, rhs: u64) -> El {
        let mut r = self;

        r.mul_scalar_assign(rhs);
        r
    }
}

impl Mul<El> for El {
    type Output = El;

    fn mul(self, rhs: El) -> El {
        let mut r = self;

        r.mul_assign(&rhs);
        r
    }
}

impl<'a, 'b> Mul<&'a El> for &'b El {
    type Output = El;

    fn mul(self, rhs: &'a El) -> El {
        let mut r = *self;

        r.mul_assign(rhs);
        r
    }
}

impl MulAssign<u64> for El {
    fn mul_assign(&mut self, rhs: u64) {
        self.mul_scalar_assign(rhs)
    }
}

impl MulAssign<El> for El {
    fn mul_assign(&mut self, rhs: El) {
        self.mul_assign(&rhs)
    }
}


impl<'a> MulAssign<&'a El> for El {
    fn mul_assign(&mut self, rhs: &'a El) {
        self.mul_fe_assign(rhs);
    }
}

impl Sub<El> for El {
    type Output = El;

    fn sub(self, rhs: El) -> El {
        let mut r = self;

        r.sub_assign(&rhs);
        r
    }
}

impl<'a, 'b> Sub<&'a El> for &'b El {
    type Output = El;

    fn sub(self, rhs: &'a El) -> El {
        let mut r = *self;

        r.sub_assign(rhs);
        r
    }
}

impl<'a> SubAssign<&'a El> for El {
    fn sub_assign(&mut self, rhs: &'a El) {
        // r = r + (-a)
        self.d[0] += 0xffffefffffc2fu64 * 2 - rhs.d[0];
        self.d[1] += 0xfffffffffffffu64 * 2 - rhs.d[1];
        self.d[2] += 0xfffffffffffffu64 * 2 - rhs.d[2];
        self.d[3] += 0xfffffffffffffu64 * 2 - rhs.d[3];
        self.d[4] += 0x0ffffffffffffu64 * 2 - rhs.d[4];
    }
}

impl SubAssign<El> for El {
    fn sub_assign(&mut self, rhs: El) {
        self.sub_assign(&rhs)
    }
}

impl Ord for El {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            if self.d[i] > other.d[i] {
                return Ordering::Greater;
            }
            if self.d[i] < other.d[i] {
                return Ordering::Less;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for El {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for El {
    fn eq(&self, rhs: &Self) -> bool {
        let mut a = *self;
        let mut b = *rhs;

        a.reduce();
        b.reduce();
        a.d[0] == b.d[0] && a.d[1] == b.d[1] && a.d[2] == b.d[2] && a.d[3] == b.d[3] && a.d[4] == b.d[4]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds_a_field_element() {
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffffefffffc2eu64,
        );
        let b = &a;
        let r = a + *b;
        let rb = &r;
        let mut r2 = r.add(*rb);

        r2.reduce();
        // r2 = ((p - 1 + p - 1) + (p - 1 + p - 1)) % p
        let expected = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffffefffffc2bu64,
        );
        assert_eq!(r2, expected);
    }

    #[test]
    fn it_mult_a_field_element() {
        // A = p - 2^42
        // B = p - 2^43
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffbfefffffc2fu64,
        );
        let b = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffff7fefffffc2fu64,
        );
        let mut r = a * b;

        r.reduce();
        // r = ((p - 2^42) x (p - 2^43)) % p
        let expected = El::new(
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000200000u64,
            0x0000000000000000u64,
        );
        assert_eq!(r, expected);
    }

    #[test]
    fn it_mults_a_field_element_2() {
        // a = p - 1
        // b = p - 1
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffffefffffc2eu64,
        );
        let b = a;
        let mut r = a * b;

        r.reduce();

        // r = ((p - 1) x (p - 1)) % p
        let expected = El::new(
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000001u64,
        );
        assert_eq!(r, expected);
    }

    #[test]
    fn it_square_a_field_element() {
        // A = p - 1000
        let mut a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffffeffffec2fu64,
        );

        a.square();
        a.reduce();
        // r = ((p - 1000)^2) % p
        let expected = El::new(
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000001000000u64,
        );
        assert_eq!(a, expected);
    }

    #[test]
    fn it_mult_a_scalar() {
        // A = p - 2^42
        // N = 0x942
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffbfefffffc2fu64,
        );
        let mut r = a * 0x942u64;
        r.reduce();
        // r = ((p - 2^42) * 0x942) % p
        let expected = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffdaf7fefffffc2fu64,
        );
        assert_eq!(r, expected);
    }

    #[test]
    fn it_tests_equality() {
        // A=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffbfefffffc2f = p - 2^42
        // N=0x942
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffbfefffffc2fu64,
        );
        let mut r = a * 0x942u64;
        let r2 = r;

        r.reduce();
        // r = ((p - 2^42) * 0x942) % p
        assert_eq!(r, r);
        assert_eq!(r, r2);
    }

    #[test]
    fn it_tests_ordering() {
        // A=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffbfefffffc2f = p - 2^42
        // N=0x942
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffbfefffffc2fu64,
        );
        let b = a + El::new(0x0, 0x0, 0x0, 0x1);
        let mut r = a * 0x942u64;
        r.reduce();

        // r = ((p - 2^42) * 0x942) % p
        assert!(r < a);
        assert!(a > r);
        assert!(r >= r);
        assert!(a <= a);
        assert!(b > a);
        assert!(b >= a);
    }

    #[test]
    fn it_tests_inverse() {
        // a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffbfefffffc2f = p - 2^42
        let a = El::new(
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xffffffffffffffffu64,
            0xfffffbfefffffc2fu64,
        );
        let n_1 = El::new(0x0, 0x0, 0x0, 0x1);

        let mut a_inv = a;
        a_inv.inverse();

        let mut r = a * a_inv;
        r.reduce();
        assert_eq!(r, n_1);
    }

    #[test]
    fn it_tests_inverse2() {
        let mut b = El::new(
            0x9075b4ee4d4788ca,
            0xbb49f7f81c221151,
            0xfa2f68914d0aa833,
            0x388fa11ff621a970
        );
        let r2 = El::new(
            0xb7e31a064ed74d31,
            0x4de79011c5f0a46a,
            0xc155602353dc3d34,
            0x0fbeaeec9767a6a6
        );
        b.inverse();
        assert_eq!(b, r2);
    }

    #[test]
    fn it_tests_inverse3() {
        let mut c = El::new(
            0x955a14ded1a61169,
            0x67f7af027561b409,
            0xf3c66ca8c2c5dcad,
            0x67dfe18cbfa9fa6c
        );
        let r = El::new(
            0x1b17ded65c85729d,
            0x4523ed7e305c613a,
            0x10400c3e2e8ef0ed,
            0x06fce4838dea63b8
        );
        c.inverse();
        assert_eq!(c, r);
    }

}
