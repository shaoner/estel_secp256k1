use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign};

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

    pub fn is_zero(&self) -> bool {
        self.d[0] | self.d[1] | self.d[2] | self.d[3] | self.d[4] == 0
    }

    pub fn mul_scalar_assign(&mut self, n: u64) {
        debug_assert!(n < 0x1000);

        self.d[0] *= n;
        self.d[1] *= n;
        self.d[2] *= n;
        self.d[3] *= n;
        self.d[4] *= n;
    }

    pub fn mul_fe(&mut self, b: &Self) {
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
        if d4 > M48 || (d4 == M48 && d3 | d2 | d1 == M52 && d0 >= 0xffffefffffc2f) {
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
        self.mul_fe(rhs);
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

        println!("r = {:?}", r);
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

}