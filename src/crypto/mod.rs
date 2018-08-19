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
use secstr::SecStr;

use {EncryptionKey, Error as LibError, HmacKey, Result};

#[derive(Debug)]
pub enum Error {
    CipherError(SymmetricCipherError),
}

impl From<SymmetricCipherError> for ::Error {
    fn from(s: SymmetricCipherError) -> Self {
        LibError::Crypto(Error::CipherError(s))
    }
}

/// Applies the opvault PBKDF2 derivation and returns the derived key.
pub fn pbkdf2(pw: &SecStr, salt: &SecStr, iterations: u32) -> Result<SecStr> {
    let mut derived = SecStr::new(vec![0u8; 64]);
    let mut mac = Hmac::new(Sha512::new(), pw.unsecure());
    crypto_pbkdf2(
        &mut mac,
        salt.unsecure(),
        iterations,
        derived.unsecure_mut(),
    );
    Ok(derived)
}

/// Computes the SHA512 hash of the provided data.
pub fn hash_sha512(data: &[u8]) -> Result<[u8; 64]> {
    let mut hash = [0u8; 64];
    let mut digest = Sha512::new();
    digest.input(data);
    digest.result(&mut hash);
    Ok(hash)
}

/// Decrypts the provided data using AES CBC with no padding and SHA512.
pub fn decrypt_data(data: &[u8], decrypt_key: &EncryptionKey, iv: &SecStr) -> Result<SecStr> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        decrypt_key.unsecure(),
        iv.unsecure(),
        NoPadding,
    );
    let mut read_buffer = RefReadBuffer::new(data);

    // CBC block size is 16 bytes, so the output needs to be larger than Ceil[data / 16] * 16
    let mut output = Vec::with_capacity(((data.len() - 1) / 16 + 1) * 16);
    let mut decrypt_buffer = SecStr::new(vec![0; 4096]);
    let mut decrypt_buffer_writer = RefWriteBuffer::new(decrypt_buffer.unsecure_mut());

    loop {
        let result = match decryptor.decrypt(&mut read_buffer, &mut decrypt_buffer_writer, true) {
            Ok(r) => r,
            Err(e) => {
                // Ensure that we zero out the output on error.
                drop(SecStr::new(output));
                return Err(e.into());
            }
        };
        output.extend_from_slice(decrypt_buffer_writer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => (),
        }
    }

    Ok(SecStr::new(output))
}

/// Verify that the provided [data], of the format
///
/// [data bytes][32-byte SHA256 HMAC]
///
/// correctly corresponds to the [hmac_key]
pub fn verify_data(data_with_hash_suffix: &[u8], hmac_key: &HmacKey) -> Result<bool> {
    assert!(data_with_hash_suffix.len() >= 32);
    let (data, mac) = data_with_hash_suffix.split_at(data_with_hash_suffix.len() - 32);
    let mut hmac = Hmac::new(Sha256::new(), hmac_key.unsecure());
    hmac.input(data);
    let result = hmac.result();

    // Make sure we do a constant-time compare!
    Ok(MacResult::new(mac) == result)
}

/// Computes the 32-byte SHA256 HMAC for the data enclosed by the closure [cb].
pub fn hmac(hmac_key: &HmacKey, cb: impl FnOnce(&mut HmacWrapper) -> Result<()>) -> Result<SecStr> {
    let mut hmac = Hmac::new(Sha256::new(), hmac_key.unsecure());
    cb(&mut HmacWrapper { mac: &mut hmac })?;
    let mut out = SecStr::new(vec![0u8; 32]);
    hmac.raw_result(out.unsecure_mut());
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
