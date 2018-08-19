// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use secstr::SecStr;
use std::ops::Deref;

#[derive(Debug)]
pub struct EncryptionKey(pub SecStr);

impl Deref for EncryptionKey {
    type Target = SecStr;
    fn deref(&self) -> &SecStr {
        &self.0
    }
}

#[derive(Debug)]
pub struct HmacKey(pub SecStr);

impl Deref for HmacKey {
    type Target = SecStr;
    fn deref(&self) -> &SecStr {
        &self.0
    }
}

/// This contains a pair of keys used for encryption and verification of the
/// different aspects of the format.
#[derive(Debug)]
pub struct Key {
    encryption_key: EncryptionKey,
    verification_key: HmacKey,
}

impl Key {
    /// Construct a new [Key] from the securely concatenated key-pair.
    pub fn new(concatenated_key: &SecStr) -> Self {
        let data = concatenated_key.unsecure();
        assert_eq!(data.len(), 64);
        Key {
            encryption_key: EncryptionKey(SecStr::from(&data[..32])),
            verification_key: HmacKey(SecStr::from(&data[32..64])),
        }
    }

    /// Retrieve a reference to the key used for encryption.
    #[inline]
    pub fn encryption(&self) -> &EncryptionKey {
        &self.encryption_key
    }

    /// Retrieve a reference to the key used for verification (HMAC)
    #[inline]
    pub fn verification(&self) -> &HmacKey {
        &self.verification_key
    }
}

/// Alias we use to indicate we expect the master key
#[derive(Debug)]
pub struct MasterKey {
    pub key: Key,
}

impl Deref for MasterKey {
    type Target = Key;

    fn deref(&self) -> &Key {
        &self.key
    }
}

/// Alias we use to indicate we expect the overview key
#[derive(Debug)]
pub struct OverviewKey {
    pub key: Key,
}

impl Deref for OverviewKey {
    type Target = Key;

    fn deref(&self) -> &Key {
        &self.key
    }
}

/// Alias we use to indicate we expect an item's key
#[derive(Debug)]
pub struct ItemKey {
    pub key: Key,
}

impl Deref for ItemKey {
    type Target = Key;

    fn deref(&self) -> &Key {
        &self.key
    }
}
