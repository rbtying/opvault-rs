// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crypto::{decrypt_data, verify_data};

use secstr::SecStr;
use Key;
use Result;

/// The header for this kind of data
static OPDATA_STR: &'static [u8; 8] = b"opdata01";

#[derive(Debug)]
pub enum OpdataError {
    InvalidHeader,
    InvalidHmac,
}

pub fn decrypt(data: &SecStr, key: &Key) -> Result<SecStr> {
    // The first step is to hash the data (minus the MAC itself)
    if !verify_data(data.unsecure(), key.verification())? {
        return Err(super::Error::OpdataError(OpdataError::InvalidHmac));
    }

    let mut cursor = Cursor::new(data.unsecure());

    // The data is intact, let's see whether it's well formed now and decrypt
    let mut header = [0u8; 8];
    cursor.read_exact(&mut header)?;

    if &header != OPDATA_STR {
        return Err(OpdataError::InvalidHeader.into());
    }

    let len = cursor.read_u64::<LittleEndian>()?;
    let mut iv = SecStr::from(vec![0u8; 16]);
    cursor.read_exact(iv.unsecure_mut())?;

    let crypt_data = &data.unsecure()[32..data.unsecure().len() - 32];

    let decrypted = decrypt_data(crypt_data, key.encryption(), &iv)?;
    let unpadded = SecStr::from(&decrypted.unsecure()[crypt_data.len() - (len as usize)..]);

    Ok(unpadded)
}
