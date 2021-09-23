use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign};

use crate::field::El;
use crate::scalar::Scalar;

const G_X: El = El::new(0x79be667ef9dcbbac,
                        0x55a06295ce870b07,
                        0x029bfcdb2dce28d9,
                        0x59f2815b16f81798);

const G_Y: El = El::new(0x483ada7726a3c465,
                        0x5da4fbfc0e1108a8,
                        0xfd17b448a6855419,
                        0x9c47d08ffb10d4b8);

pub const G: Pt = Pt::new(G_X, G_Y);

pub const N: Scalar = Scalar::new(0xffffffffffffffff,
                                  0xfffffffffffffffe,
                                  0xbaaedce6af48a03b,
                                  0xbfd25e8cd0364141);

#[derive(Clone, Copy, Eq)]
pub struct Pt {
    pub x: El,
    pub y: El,
    pub inf: bool
}

pub const INFINITY: Pt = Pt {
    x: El::new(0, 0, 0, 0),
    y: El::new(0, 0, 0, 0),
    inf: true,
};

impl Pt {
    pub const fn new(x: El, y: El) -> Self {
        Self { x, y, inf: false }
    }

    pub fn add_inner(&mut self, rhs: &Self) {
        if self.inf {
            *self = *rhs;
            return;
        }
        if rhs.inf {
            return;
        }
        if self.x == rhs.x && self.y != rhs.y {
            *self = INFINITY;
        }
        if self.y.is_zero() && self == rhs {
            *self = INFINITY;
        }

        let (mut s, mut x3, mut y3): (El, El, El);

        if self.x != rhs.x {
            // s = (y - y2) / (x - x2)
            // x3 = s^2 - x - x2
            let mut _x = self.x - rhs.x;
            _x.inverse();
            s = (self.y - rhs.y) * _x;
            s.reduce();

            let mut s2 = s;
            s2.square();
            s2.reduce();
            x3 = s2 - self.x - rhs.x;
            x3.reduce();
        } else {
            // s = (3x^2 + a) / 2y
            // x3 = s^2 - 2x
            let mut t2 = self.x;
            let mut _2y = self.y * 0x2u64;
            _2y.inverse();
            t2.square();
            t2 *= 0x3u64;
            t2.reduce();
            s = t2 * _2y;
            s.reduce();

            let mut s2 = s;
            s2.square();
            s2.reduce();
            x3 = s2 - self.x * 0x2u64;
            x3.reduce();
        }
        // y3 = s(x - x3) - y
        y3 = s * (self.x - x3) - self.y;
        y3.reduce();

        self.x = x3;
        self.y = y3;
    }

    pub fn mul_scalar_inner(&mut self, a: &Scalar) {
        let mut n = *a;

        if n >= N {
            n -= N;
        }

        let mut r = INFINITY;
        let mut me = *self;

        loop {
            if !n.is_even() {
                r.add_inner(&me);
            }
            n.div2();
            if !n.is_zero() {
                let mme = me;
                me.add_inner(&mme);
            } else {
                break;
            }
        }
        *self = r;
    }
}

impl fmt::Debug for Pt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.inf {
            write!(f, "Infinity")
        } else {
            write!(f, "Pt ({:?}, {:?})", self.x, self.y)
        }
    }
}

impl Default for Pt {
    fn default() -> Self {
        Self { x: El::default(), y: El::default(), inf: true }
    }
}

impl Add<Pt> for Pt {
    type Output = Pt;

    fn add(self, rhs: Pt) -> Pt {
        let mut r = self;

        r.add_assign(&rhs);
        r
    }
}

impl<'a, 'b> Add<&'a Pt> for &'b Pt {
    type Output = Pt;

    fn add(self, rhs: &'a Pt) -> Pt {
        let mut r = *self;

        r.add_assign(rhs);
        r
    }
}

impl<'a> AddAssign<&'a Pt> for Pt {
    fn add_assign(&mut self, rhs: &'a Pt) {
        self.add_inner(rhs);
    }
}

impl AddAssign<Pt> for Pt {
    fn add_assign(&mut self, rhs: Pt) {
        self.add_assign(&rhs)
    }
}

impl Mul<&Scalar> for Pt {
    type Output = Pt;

    fn mul(self, rhs: &Scalar) -> Pt {
        let mut r = self;

        r.mul_assign(rhs);
        r
    }
}

impl MulAssign<&Scalar> for Pt {
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.mul_scalar_inner(rhs)
    }
}

impl PartialEq for Pt {
    fn eq(&self, rhs: &Self) -> bool {
        if self.inf {
            return rhs.inf;
        }
        if rhs.inf {
            return self.inf;
        }

        self.x == rhs.x && self.y == rhs.y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_checks_addition() {
        let p = Pt::new(El::new(0x8b4b5f165df3c2be,
                                0x8c6244b5b7456388,
                                0x43e4a781a15bcd1b,
                                0x69f79a55dffdf80c),
                        El::new(0x4aad0a6f68d308b4,
                                0xb3fbd7813ab0da04,
                                0xf9e336546162ee56,
                                0xb3eff0c65fd4fd36));
        let mut p2 = p;
        let res = Pt::new(El::new(0xed0c5ce4e1329171,
                                  0x8ce17c7ec83c6110,
                                  0x71af64ee417c997a,
                                  0xbb3f26714755e4be),
                          El::new(0x221a9fc7bc2345bd,
                                  0xbf3dad7f5a7ea680,
                                  0x49d93925763ddab1,
                                  0x63f9fa6ea07bf42f));

        p2.add_inner(&p);

        assert_eq!(p2, res);
    }

    #[test]
    fn it_checks_scalar_multiplication() {
        let mut p: Pt = G;
        let mut a = N;
        let n_1 = Scalar::from_u64(1);
        a -= n_1;
        let res = Pt::new(El::new(0x79be667ef9dcbbac,
                                  0x55a06295ce870b07,
                                  0x029bfcdb2dce28d9,
                                  0x59f2815b16f81798),
                          El::new(0xb7c52588d95c3b9a,
                                  0xa25b0403f1eef757,
                                  0x02e84bb7597aabe6,
                                  0x63b82f6f04ef2777));

        p.mul_scalar_inner(&a);

        assert_eq!(p, res);
    }
}
