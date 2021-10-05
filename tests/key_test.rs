use estel_secp256k1::generate_keypair_from_seed;

#[test]
fn it_verify_a_signature_from_buffer() {
    let (privkey, pubkey) = generate_keypair_from_seed("n00b".as_bytes());

    let msg = "Hello World".as_bytes();

    // create a signature
    let sig = privkey.sign_buffer(&msg);
    // verify signature
    assert!(pubkey.verify_buffer(&msg, &sig));
}
