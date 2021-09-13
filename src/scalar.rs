use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::mem;

pub const P: Scalar = Scalar::new(0x0000000000000000,
                                  0xffffffffffffffff,
                                  0xffffffffffffffff,
                                  0xffffffffffffffff,
                                  0xfffffffefffffc2f);

/// Order of the secp256k1 group
const SECP256K1_N_0: u64 = 0xbfd25e8cd0364141u64;
const SECP256K1_N_1: u64 = 0xbaaedce6af48a03bu64;
const SECP256K1_N_2: u64 = 0xfffffffffffffffeu64;
const SECP256K1_N_3: u64 = 0xffffffffffffffffu64;

/// 2^256 - N, used in reductions
const SECP256K1_NI_0: u64 = 0x402da1732fc9bebfu64;
const SECP256K1_NI_1: u64 = 0x4551231950b75fc4u64;

/// Represent a i320 with support for carry
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Scalar {
    pub d: [u64; 5]
}

impl Scalar {
    pub const fn new(d4: u64, d3: u64, d2: u64, d1: u64, d0: u64) -> Self {
        Self { d: [d0, d1, d2, d3, d4] }
    }

    pub const fn from_u64(n: u64) -> Self {
        Self::new(0, 0, 0, 0, n)
    }

    /// Convert bytes (big endian) to scalar
    pub const fn from_bytes(b: &[u8; 32]) -> Self {
        let d0 = (b[31] as u64) << 0
            | (b[30] as u64) << 8
            | (b[29] as u64) << 16
            | (b[28] as u64) << 24
            | (b[27] as u64) << 32
            | (b[26] as u64) << 40
            | (b[25] as u64) << 48
            | (b[24] as u64) << 56;

        let d1 = (b[23] as u64) << 0
            | (b[22] as u64) << 8
            | (b[21] as u64) << 16
            | (b[20] as u64) << 24
            | (b[19] as u64) << 32
            | (b[18] as u64) << 40
            | (b[17] as u64) << 48
            | (b[16] as u64) << 56;

        let d2 = (b[15] as u64) << 0
            | (b[14] as u64) << 8
            | (b[13] as u64) << 16
            | (b[12] as u64) << 24
            | (b[11] as u64) << 32
            | (b[10] as u64) << 40
            | (b[9] as u64) << 48
            | (b[8] as u64) << 56;

        let d3 = (b[7] as u64) << 0
            | (b[6] as u64) << 8
            | (b[5] as u64) << 16
            | (b[4] as u64) << 24
            | (b[3] as u64) << 32
            | (b[2] as u64) << 40
            | (b[1] as u64) << 48
            | (b[0] as u64) << 56;

        Self { d: [d0, d1, d2, d3, 0] }
    }

    /// Convert scalar to bytes in big endian
    /// Assuming it is normalized e.g. 256 bits
    pub fn to_bytes(&self) -> [u8; 32] {
        debug_assert_eq!(self.d[4], 0);

        let mut b = [0u8; 32];

        b[31] = self.d[0] as u8;
        b[30] = (self.d[0] >> 8) as u8;
        b[29] = (self.d[0] >> 16) as u8;
        b[28] = (self.d[0] >> 24) as u8;
        b[27] = (self.d[0] >> 32) as u8;
        b[26] = (self.d[0] >> 40) as u8;
        b[25] = (self.d[0] >> 48) as u8;
        b[24] = (self.d[0] >> 56) as u8;

        b[23] = self.d[1] as u8;
        b[22] = (self.d[1] >> 8) as u8;
        b[21] = (self.d[1] >> 16) as u8;
        b[20] = (self.d[1] >> 24) as u8;
        b[19] = (self.d[1] >> 32) as u8;
        b[18] = (self.d[1] >> 40) as u8;
        b[17] = (self.d[1] >> 48) as u8;
        b[16] = (self.d[1] >> 56) as u8;

        b[15] = self.d[2] as u8;
        b[14] = (self.d[2] >> 8) as u8;
        b[13] = (self.d[2] >> 16) as u8;
        b[12] = (self.d[2] >> 24) as u8;
        b[11] = (self.d[2] >> 32) as u8;
        b[10] = (self.d[2] >> 40) as u8;
        b[9] = (self.d[2] >> 48) as u8;
        b[8] = (self.d[2] >> 56) as u8;

        b[7] = self.d[3] as u8;
        b[6] = (self.d[3] >> 8) as u8;
        b[5] = (self.d[3] >> 16) as u8;
        b[4] = (self.d[3] >> 24) as u8;
        b[3] = (self.d[3] >> 32) as u8;
        b[2] = (self.d[3] >> 40) as u8;
        b[1] = (self.d[3] >> 48) as u8;
        b[0] = (self.d[3] >> 56) as u8;

        return b;
    }

    pub fn is_even(&self) -> bool {
        self.d[0] & 0x1 == 0x0
    }

    pub fn is_zero(&self) -> bool {
        (self.d[0] | self.d[1] | self.d[2] | self.d[3] | self.d[4]) == 0
    }

    pub fn div2(&mut self) {
        let mut t: u64;

        t = self.d[1] & 0x01;
        self.d[0] = (t << 63) | (self.d[0] >> 1);
        t = self.d[2] & 0x01;
        self.d[1] = (t << 63) | (self.d[1] >> 1);
        t = self.d[3] & 0x01;
        self.d[2] = (t << 63) | (self.d[2] >> 1);
        t = self.d[4] & 0x01;
        self.d[3] = (t << 63) | (self.d[3] >> 1);
        t = self.d[4] >> 63;
        self.d[4] = (t << 63) | (self.d[4] >> 1);
    }

    fn div2_mod(&mut self, m: &Self) {
        if !self.is_even() {
            self.add_assign(m);
        }
        self.div2()
    }

    pub fn normalize(&mut self, m: &Self) {
        let s = self.d[4] >> 63;

        if s > 0 {
            // self < 0
            self.add_assign(m);
            let s2 = self.d[4] >> 63;

            if s2 > 0 {
                // self < 0
                self.add_assign(m);
            }
        } else if *self >= *m {
            // self >= m
            *self -= m;
        }
    }

    pub fn modinv(&mut self, m: &Self) {
        let mut b = *m;
        let mut x = Self { d: [1, 0, 0, 0, 0] };
        let mut y = Self { d: [0, 0, 0, 0, 0] };

        while !self.is_zero() {
            if self.is_even() {
                self.div2();
                x.div2_mod(m);
            } else {
                if *self < b {
                    mem::swap(self, &mut b);
                    mem::swap(&mut x, &mut y);
                }
                *self -= b;
                self.div2();
                x -= y;
                x.div2_mod(m);
            }
        }
        y.normalize(m);
        *self = y;
    }
}

macro_rules! define_ops {
    ($c0: ident, $c1: ident, $c2: ident) => {
        #[allow(unused_macros)]
        macro_rules! muladd {
            ($a: expr, $b: expr) => {
                let a = $a;
                let b = $b;
                let t = (a as u128) * (b as u128);
                let mut th = (t >> 64) as u64;
                let tl = t as u64;
                $c0 = $c0.wrapping_add(tl);
                th = th.wrapping_add(if $c0 < tl { 1 } else { 0 });
                $c1 = $c1.wrapping_add(th);
                $c2 = $c2.wrapping_add(if $c1 < th { 1 } else { 0 });
                debug_assert!($c1 >= th || $c2 != 0);
            };
        }

        #[allow(unused_macros)]
        macro_rules! muladd_fast {
            ($a: expr, $b: expr) => {
                let a = $a;
                let b = $b;
                let t = (a as u128) * (b as u128);
                let mut th = (t >> 64) as u64;
                let tl = t as u64;
                $c0 = $c0.wrapping_add(tl);
                th = th.wrapping_add(if $c0 < tl { 1 } else { 0 });
                $c1 = $c1.wrapping_add(th);
                debug_assert!($c1 >= th);
            };
        }

        #[allow(unused_macros)]
        macro_rules! sumadd {
            ($a: expr) => {
                let a = $a;
                $c0 = $c0.wrapping_add(a);
                let over = if $c0 < a { 1 } else { 0 };
                $c1 = $c1.wrapping_add(over);
                $c2 = $c2.wrapping_add(if $c1 < over { 1 } else { 0 });
            };
        }

        #[allow(unused_macros)]
        macro_rules! sumadd_fast {
            ($a: expr) => {
                let a = $a;
                $c0 = $c0.wrapping_add(a);
                $c1 = $c1.wrapping_add(if $c0 < a { 1 } else { 0 });
                debug_assert!($c1 != 0 || $c0 >= a);
                debug_assert!($c2 == 0);
            };
        }

        #[allow(unused_macros)]
        macro_rules! extract {
            () => {{
                #[allow(unused_assignments)]
                {
                    let n = $c0;
                    $c0 = $c1;
                    $c1 = $c2;
                    $c2 = 0;
                    n
                }
            }};
        }

        #[allow(unused_macros)]
        macro_rules! extract_fast {
            () => {{
                #[allow(unused_assignments)]
                {
                    let n = $c0;
                    $c0 = $c1;
                    $c1 = 0;
                    debug_assert!($c2 == 0);
                    n
                }
            }};
        }
    };
}

/// Implementation for the secp256k1 order
impl Scalar {
    fn mul512(&self, b: &Scalar) -> [u64; 8] {
        let (mut c0, mut c1, mut c2): (u64, u64, u64) = (0, 0, 0);
        let (a0, a1, a2, a3, a4) = (self.d[0], self.d[1], self.d[2], self.d[3], self.d[4]);
        let (b0, b1, b2, b3, b4) = (b.d[0], b.d[1], b.d[2], b.d[3], b.d[4]);
        let mut r = [0u64; 8];

        define_ops!(c0, c1, c2);
        muladd_fast!(a0, b0);
        r[0] = extract_fast!();

        muladd!(a0, b1);
        muladd!(a1, b0);
        r[1] = extract!();

        muladd!(a0, b2);
        muladd!(a1, b1);
        muladd!(a2, b0);
        r[2] = extract!();

        muladd!(a0, b3);
        muladd!(a1, b2);
        muladd!(a2, b1);
        muladd!(a3, b0);
        r[3] = extract!();

        muladd!(a0, b4);
        muladd!(a1, b3);
        muladd!(a2, b2);
        muladd!(a3, b1);
        muladd!(a4, b0);
        r[4] = extract!();

        muladd!(a1, b4);
        muladd!(a2, b3);
        muladd!(a3, b2);
        muladd!(a4, b1);
        r[5] = extract!();

        muladd!(a2, b4);
        muladd!(a3, b3);
        muladd!(a4, b2);
        r[6] = extract!();

        muladd!(a3, b4);
        muladd!(a4, b3);
        r[7] = extract!();

        debug_assert!(c1 == 0);
        debug_assert!(c2 == 0);
        r
    }

    fn get_overflow(&self) -> u32 {
        let mut yes = 0u32;
        let mut no = 0u32;

        no |= (self.d[3] < SECP256K1_N_3) as u32;
        no |= (self.d[2] < SECP256K1_N_2) as u32;
        yes |= (self.d[2] > SECP256K1_N_2) as u32 & !no;
        no |= (self.d[1] < SECP256K1_N_1) as u32;
        yes |= (self.d[1] > SECP256K1_N_1) as u32 & !no;
        yes |= (self.d[0] >= SECP256K1_N_0) as u32 & !no;
        return yes;
    }

    fn reduce512(&mut self, r: &[u64; 8]) {
        let (mut c0, mut c1, mut c2): (u64, u64, u64);
        define_ops!(c0, c1, c2);

        let mut c: u128;
        let (n0, n1, n2, n3) = (r[4], r[5], r[6], r[7]);
        let (m0, m1, m2, m3, m4, m5): (u64, u64, u64, u64, u64, u64);
        let m6: u32;
        let (p0, p1, p2, p3): (u64, u64, u64, u64);
        let p4: u32;

        c0 = r[0];
        c1 = 0;
        c2 = 0;

        muladd_fast!(n0, SECP256K1_NI_0);
        m0 = extract_fast!();
        sumadd_fast!(r[1]);

        muladd!(n1, SECP256K1_NI_0);
        muladd!(n0, SECP256K1_NI_1);
        m1 = extract!();
        sumadd!(r[2]);
        muladd!(n2, SECP256K1_NI_0);
        muladd!(n1, SECP256K1_NI_1);
        sumadd!(n0);
        m2 = extract!();
        sumadd!(r[3]);
        muladd!(n3, SECP256K1_NI_0);
        muladd!(n2, SECP256K1_NI_1);
        sumadd!(n1);
        m3 = extract!();
        muladd!(n3, SECP256K1_NI_1);
        sumadd!(n2);
        m4 = extract!();
        sumadd_fast!(n3);
        m5 = extract_fast!();
        m6 = c0 as u32;

        c0 = m0;
        c1 = 0;
        c2 = 0;
        muladd_fast!(m4, SECP256K1_NI_0);
        p0 = extract_fast!();
        sumadd_fast!(m1);
        muladd!(m5, SECP256K1_NI_0);
        muladd!(m4, SECP256K1_NI_1);
        p1 = extract!();
        sumadd!(m2);
        muladd!(m6, SECP256K1_NI_0);
        muladd!(m5, SECP256K1_NI_1);
        sumadd!(m4);
        p2 = extract!();
        sumadd_fast!(m3);
        muladd_fast!(m6, SECP256K1_NI_1);
        sumadd_fast!(m5);
        p3 = extract_fast!();
        p4 = c0 as u32 + m6 as u32;
        debug_assert!(p4 <= 2);

        c = p0 as u128 + SECP256K1_NI_0 as u128 * p4 as u128;
        self.d[0] = c as u64;
        c >>= 64;
        c += p1 as u128 + SECP256K1_NI_1 as u128 * p4 as u128;
        self.d[1] = c as u64;
        c >>= 64;
        c += p2 as u128 + p4 as u128;
        self.d[2] = c as u64;
        c >>= 64;
        c += p3 as u128;
        self.d[3] = c as u64;
        c >>= 64;

        // reduce if overflow 2^256 (c) or N
        self.reduce(c as u32 + self.get_overflow());
    }

    pub fn reduce(&mut self, overflow: u32) {
        let mut t: u128;

        debug_assert!(overflow <= 1);

        t = self.d[0] as u128 + overflow as u128 * SECP256K1_NI_0 as u128;
        self.d[0] = t as u64;
        t >>= 64;

        t += self.d[1] as u128 + overflow as u128 * SECP256K1_NI_1 as u128;
        self.d[1] = t as u64;
        t >>= 64;

        t += self.d[2] as u128 + overflow as u128 * 1u128;
        self.d[2] = t as u64;
        t >>= 64;

        t += self.d[3] as u128;
        self.d[3] = t as u64;
    }

    pub fn mulmod_inner(&mut self, b: &Scalar) {
        let r = self.mul512(b);

        self.reduce512(&r);
    }

    pub fn mulmod(&self, b: &Scalar) -> Scalar {
        let mut res = *self;
        res.mulmod_inner(b);

        res
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}{:016x}{:016x}{:016x}{:016x}",
               self.d[4], self.d[3], self.d[2], self.d[1], self.d[0])
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, rhs: Scalar) -> Scalar {
        let mut r = self;

        r.add_assign(&rhs);
        r
    }
}

impl<'a, 'b> Add<&'a Scalar> for &'b Scalar {
    type Output = Scalar;

    fn add(self, rhs: &'a Scalar) -> Scalar {
        let mut r = *self;

        r.add_assign(rhs);
        r
    }
}

impl<'a> AddAssign<&'a Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &'a Scalar) {
        let mut t: u128;

        t = (self.d[0] as u128).wrapping_add(rhs.d[0] as u128);
        self.d[0] = t as u64;
        t >>= 64;

        t = (self.d[1] as u128).wrapping_add(t + rhs.d[1] as u128);
        self.d[1] = t as u64;
        t >>= 64;

        t = (self.d[2] as u128).wrapping_add(t + rhs.d[2] as u128);
        self.d[2] = t as u64;
        t >>= 64;

        t = (self.d[3] as u128).wrapping_add(t + rhs.d[3] as u128);
        self.d[3] = t as u64;
        t >>= 64;

        t = (self.d[4] as u128).wrapping_add(t + rhs.d[4] as u128);
        self.d[4] = t as u64;
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        self.add_assign(&rhs)
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, rhs: Scalar) -> Scalar {
        let mut r = self;

        r.sub_assign(&rhs);
        r
    }
}

impl<'a, 'b> Sub<&'a Scalar> for &'b Scalar {
    type Output = Scalar;

    fn sub(self, rhs: &'a Scalar) -> Scalar {
        let mut r = *self;

        r.sub_assign(rhs);
        r
    }
}

impl<'a> SubAssign<&'a Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &'a Scalar) {
        let mut t: u128;

        t = (self.d[0] as u128).wrapping_sub(rhs.d[0] as u128);
        self.d[0] = t as u64;
        t >>= 64;
        t &= 0x01;

        t = (self.d[1] as u128).wrapping_sub(t + rhs.d[1] as u128);
        self.d[1] = t as u64;
        t >>= 64;
        t &= 0x01;

        t = (self.d[2] as u128).wrapping_sub(t + rhs.d[2] as u128);
        self.d[2] = t as u64;
        t >>= 64;
        t &= 0x01;

        t = (self.d[3] as u128).wrapping_sub(t + rhs.d[3] as u128);
        self.d[3] = t as u64;
        t >>= 64;
        t &= 0x01;

        t = (self.d[4] as u128).wrapping_sub(t + rhs.d[4] as u128);
        self.d[4] = t as u64;
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: Scalar) {
        self.sub_assign(&rhs)
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Scalar) -> Ordering {
        if self.d[4] > other.d[4] {
            // same sign
            if (self.d[4] ^ other.d[4]) >> 63 == 0 {
                return Ordering::Greater
            } else {
                return Ordering::Less
            }
        }
        if self.d[4] < other.d[4] {
            if (self.d[4] ^ other.d[4]) >> 63 == 0 {
                return Ordering::Less
            } else {
                return Ordering::Greater
            }
        }
        // d[4] == other.d[4], same signs
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

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_div2() {
        let mut a = Scalar::new(0x0000000000000000,
                                0x0000000000000000,
                                0x0000000000000000,
                                0x0000000000000100,
                                0x0000000000000000);
        let b = Scalar::new(0x0000000000000000,
                            0x0000000000000000,
                            0x0000000000000000,
                            0x0000000000000020,
                            0x0000000000000000);

        a.div2();
        a.div2();
        a.div2();
        assert_eq!(a, b);
    }

    #[test]
    fn it_tests_ordering() {
        let a = Scalar::new(0x8000000000000000,
                            0x0000000000000000,
                            0x0000000000000000,
                            0x0000000000000000,
                            0x0000000000000000); // -2^319

        let min_1 = Scalar::new(0xffffffffffffffff,
                                0xffffffffffffffff,
                                0xffffffffffffffff,
                                0xffffffffffffffff,
                                0xffffffffffffffff); // -1

        let b = Scalar::new(0x7fffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff); // 2^319 - 1
        let n_0 = Scalar::from_u64(0);
        let n_1 = Scalar::from_u64(1);

        assert!(a < min_1);
        assert!(min_1 > a);

        assert!(b > a);
        assert!(a < b);

        assert!(b > min_1);
        assert!(min_1 < b);

        assert!(min_1 < n_0);
        assert!(n_0 > min_1);

        assert!(a < n_0);
        assert!(n_0 > a);

        assert!(b > n_0);
        assert!(n_0 < b);

        assert!(n_1 > n_0);
        assert!(n_0 < n_1);

        assert!(b > n_1);
        assert!(n_1 < b);

        assert!(min_1 < n_1);
        assert!(n_1 > min_1);
    }

    #[test]
    fn it_modinv() {
        let mut a = Scalar::new(0x0000000000000000,
                                0xffffffffffffffff,
                                0xffffffffffffffff,
                                0xffffffffffffffff,
                                0xfffffbfefffffc2f);
        let mut b = Scalar::new(0x0000000000000000,
                                0x7fffffffffffffff,
                                0xffffffffffffffff,
                                0xffffffffffffffff,
                                0xffffffff7ffffe18);
        let mut c = Scalar::new(0x0000000000000000,
                                0x0000000000000000,
                                0x0000000000000000,
                                0x0000000000000000,
                                0x0000000000111111);

        let p = Scalar::new(0x0000000000000000,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xfffffffefffffc2f);

        let res = Scalar::new(0x0000000000000000,
                              0xb88b76b2b3bfffff,
                              0xffffffffffffffff,
                              0xffffffffffffffff,
                              0xffffffff4774868d);
        let res2 = Scalar::from_u64(0x2);
        let res3 = Scalar::new(0x0,
                               0x3eb0f23eb0f23eb0,
                               0xf23eb0f23eb0f23e,
                               0xb0f23eb0f23eb0f2,
                               0x3eb0f23e72414b83);

        a.modinv(&p);
        assert_eq!(a, res);

        b.modinv(&p);
        assert_eq!(b, res2);

        c.modinv(&p);
        assert_eq!(c, res3);
    }

    #[test]
    fn it_multiply_scalars() {
        let mut n1 = Scalar::new(0x0000000000000000,
                                 0xb88b76b2b3bfffff,
                                 0xffffffffffffffff,
                                 0xffffffffffffffff,
                                 0xffffffff4774868d);
        let n2 = n1;
        let res = Scalar::new(0x0,
                              0xdb450d7d8d367a92,
                              0xca286d6fe9413357,
                              0x6f2fbc0c5131616a,
                              0x1908465a56ab3e28);


        n1.mulmod_inner(&n2);
        assert_eq!(n1, res);
    }

    #[test]
    fn it_multiply_scalars2() {
        let mut n1 = P;
        let n2 = n1;
        let res = Scalar::new(0x0,
                              0x9d671cd581c69bc5,
                              0xe697f5e1d12ab7e0,
                              0xbd57efff7678bda1,
                              0x4d8f2b05a6047403);

        n1.mulmod_inner(&n2);
        assert_eq!(n1, res);
    }
}
