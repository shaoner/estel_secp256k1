# estel / secp256k1

![crates.io](https://img.shields.io/crates/v/estel_secp256k1.svg)
![build status](https://github.com/alexlren/estel_secp256k1/actions/workflows/ci.yaml/badge.svg)

A rust library implementing [secp256k1](https://www.secg.org/sec2-v2.pdf#subsubsection.2.4.1) ECDSA

/!\ This library is still experimental and the API may change

## Example

### Signature

```rust
let msg = "Hello World";
let password = "n00b";
let msg = msg.as_bytes();
let secret = hash256(password.as_bytes());
let secret = Scalar::from_bytes(&secret);
let pvk = PrivateKey::new(secret);
let sig = pvk.sign_from_buffer(&msg);
```

### Verify a signature associated to a buffer

```rust
let msg = "Hello World";
let msg = msg.as_bytes();
let pubk = PublicKey::from_secret(&secret);
pubk.verify_buffer(&msg, &sig);
```
