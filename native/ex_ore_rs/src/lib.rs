use ore_rs::{ORECipher, OREEncrypt, scheme::bit2::OREAES128};
use rustler::{Binary, Env, OwnedBinary};
use std::cmp::Ordering;

#[rustler::nif]
fn encrypt_32_8<'a>(env: Env<'a>, n: u32, k1: Binary, k2: Binary, seed: Binary) -> Binary<'a> {
    let (mut k1a, mut k2a, mut sa) = ([0u8; 16], [0u8; 16], [0u8; 8]);
    k1a.copy_from_slice(k1.as_slice());
    k2a.copy_from_slice(k2.as_slice());
    sa.copy_from_slice(seed.as_slice());
    let mut ore: OREAES128 = ORECipher::init(k1a, k2a, &sa).unwrap();

    let ct = n.encrypt(&mut ore).unwrap().to_bytes();
    let mut bin = OwnedBinary::new(ct.len()).unwrap();
    bin.as_mut_slice().copy_from_slice(&ct);
    Binary::from_owned(bin, env)
}

#[rustler::nif]
fn compare_32_8(a: Binary, b: Binary) -> i8 {
    match OREAES128::compare_raw_slices(a.as_slice(), b.as_slice()).expect("failed to compare ciphertexts") {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1
    }
}

#[rustler::nif]
fn encrypt_64_8<'a>(env: Env<'a>, n: u64, k1: Binary, k2: Binary, seed: Binary) -> Binary<'a> {
    let (mut k1a, mut k2a, mut sa) = ([0u8; 16], [0u8; 16], [0u8; 8]);
    k1a.copy_from_slice(k1.as_slice());
    k2a.copy_from_slice(k2.as_slice());
    sa.copy_from_slice(seed.as_slice());
    let mut ore: OREAES128 = ORECipher::init(k1a, k2a, &sa).unwrap();

    let ct = n.encrypt(&mut ore).unwrap().to_bytes();
    let mut bin = OwnedBinary::new(ct.len()).unwrap();
    bin.as_mut_slice().copy_from_slice(&ct);
    Binary::from_owned(bin, env)
}

#[rustler::nif]
fn compare_64_8(a: Binary, b: Binary) -> i8 {
    match OREAES128::compare_raw_slices(a.as_slice(), b.as_slice()).expect("failed to compare ciphertexts") {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1
    }
}

rustler::init!("Elixir.ExOreRs", [encrypt_32_8, compare_32_8, encrypt_64_8, compare_64_8]);
