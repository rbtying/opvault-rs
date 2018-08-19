// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Implementation of opvault cryptographic primitives using rust-crypto

use rust_crypto::aes;
use rust_crypto::blockmodes::NoPadding;
use rust_crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use rust_crypto::digest::Digest;
use rust_crypto::hmac::Hmac;
use rust_crypto::mac::{Mac, MacResult};
use rust_crypto::pbkdf2::pbkdf2 as crypto_pbkdf2;
use rust_crypto::sha2::{Sha256, Sha512};
use rust_crypto::symmetriccipher::SymmetricCipherError;

use {Error as LibError, HmacKey, Result};

#[derive(Debug)]
pub enum Error {
    CipherError(SymmetricCipherError),
}

impl From<SymmetricCipherError> for ::Error {
    fn from(s: SymmetricCipherError) -> Self {
        LibError::Crypto(Error::CipherError(s))
    }
}

pub fn pbkdf2(pw: &[u8], salt: &[u8], iterations: u32) -> Result<[u8; 64]> {
    let mut derived = [0u8; 64];
    let mut mac = Hmac::new(Sha512::new(), pw);
    crypto_pbkdf2(&mut mac, salt, iterations, &mut derived);
    Ok(derived)
}

pub fn hash_sha512(data: &[u8]) -> Result<[u8; 64]> {
    let mut hash = [0u8; 64];
    let mut digest = Sha512::new();
    digest.input(data);
    digest.result(&mut hash);
    Ok(hash)
}

pub fn decrypt_data(data: &[u8], decrypt_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize256, decrypt_key, iv, NoPadding);
    let mut read_buffer = RefReadBuffer::new(data);

    let mut output = Vec::new();
    let mut decrypt_buffer = [0; 4096];
    let mut decrypt_buffer_writer = RefWriteBuffer::new(&mut decrypt_buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut decrypt_buffer_writer, true)?;
        output.extend_from_slice(decrypt_buffer_writer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => (),
        }
    }

    Ok(output)
}

/// Verify that the provided [data], of the format
///
/// [data bytes][32-byte SHA256 HMAC]
///
/// correctly corresponds to the [hmac_key]
pub fn verify_data(data_with_hash_suffix: &[u8], hmac_key: &HmacKey) -> Result<bool> {
    assert!(data_with_hash_suffix.len() >= 32);
    let (data, mac) = data_with_hash_suffix.split_at(data_with_hash_suffix.len() - 32);
    let mut hmac = Hmac::new(Sha256::new(), hmac_key);
    hmac.input(data);
    let result = hmac.result();

    // Make sure we do a constant-time compare!
    Ok(MacResult::new(mac) == result)
}

/// Computes the 32-byte SHA256 HMAC for the data enclosed by the closure [cb].
pub fn hmac(
    hmac_key: &HmacKey,
    cb: impl FnOnce(&mut HmacWrapper) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut hmac = Hmac::new(Sha256::new(), hmac_key);
    cb(&mut HmacWrapper { mac: &mut hmac })?;
    let mut out = [0u8; 32];
    hmac.raw_result(&mut out);
    Ok(out)
}

/// A thin wrapper around [Hmac<Sha256>] which doesn't require the caller to import from rust_crypto.
pub struct HmacWrapper<'a> {
    mac: &'a mut Hmac<Sha256>,
}

impl<'a> HmacWrapper<'a> {
    pub fn input(&mut self, data: &[u8]) -> Result<()> {
        self.mac.input(data);
        Ok(())
    }
}
