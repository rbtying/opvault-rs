// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Read and decrypt the OPVault format
//!
//! This is the format used by 1password, including for file-based
//! synchronization between computers.
//!
//! The user's password unlocks the vault by being converted into four paired
//! keys. Each pair of keys lets us verify the integrity of the data before
//! trying to decrypt it.
//!
//! The format is described at https://support.1password.com/opvault-design/

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate base64;
extern crate byteorder;
extern crate crypto as rust_crypto;
extern crate secstr;
extern crate uuid;

use std::convert;
use std::io;
use std::result;
use std::string::FromUtf8Error;

pub use uuid::Uuid;

mod opdata01;
pub use opdata01::OpdataError;

mod attachment;
mod crypto;
mod folder;
mod item;
mod key;
mod opcldat;
mod profile;
mod vault;

mod detail;
mod overview;

pub use attachment::{Attachment, AttachmentIterator};
pub use folder::Folder;
pub use item::{Category, Item};
pub use key::{EncryptionKey, HmacKey, ItemKey, Key, MasterKey, OverviewKey};
pub use profile::Profile;
pub use vault::{LockedVault, UnlockedVault};

pub use detail::{
    Detail, Field, FieldKind, FieldValue, Generic, HtmlForm, Login, LoginField, LoginFieldKind,
    Section,
};
pub use overview::{Overview, URL};

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    JsonError(serde_json::Error),
    Base64Error(base64::DecodeError),
    FromUtf8Error(FromUtf8Error),
    OpdataError(OpdataError),
    Crypto(crypto::Error),
    ItemError,
    UuidError(uuid::ParseError),
    OpcldatError,
}

impl convert::From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl convert::From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}

impl convert::From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64Error(e)
    }
}

impl convert::From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

impl convert::From<OpdataError> for Error {
    fn from(e: OpdataError) -> Self {
        Error::OpdataError(e)
    }
}

impl convert::From<uuid::ParseError> for Error {
    fn from(e: uuid::ParseError) -> Self {
        Error::UuidError(e)
    }
}

pub type Result<T> = result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use std::path::Path;

    use secstr::SecStr;

    use {LockedVault, Uuid};

    #[test]
    fn read_vault() {
        let vault = LockedVault::open(Path::new("onepassword_data")).expect("vault");

        let unlocked = vault
            .unlock(&SecStr::new(b"freddy".to_vec()))
            .expect("unlock");
        assert_eq!(29, unlocked.get_items().count());
        assert_eq!(3, unlocked.folders.len());

        for (_uuid, folder) in &unlocked.folders {
            let _overview = folder.overview().expect("folder overview");
        }

        for item in unlocked.get_items() {
            let _overview = item.overview().expect("item overview");
            let _decrypted = item.detail().expect("item detail");
        }

        let item_uuid = Uuid::parse_str("F2DB5DA3FCA64372A751E0E85C67A538").expect("uuid");
        let item = unlocked.get_item(&item_uuid).expect("item lookup");
        let _overview = item.overview().expect("item overview");
        let _decrypted = item.detail().expect("item detail");
        assert_eq!(2, item.get_attachments().expect("attachments").count());
        let att_uuid = Uuid::parse_str("23F6167DC1FB457A8DE7033ACDCD06DB").expect("uuid");
        let _att = item.get_attachment(&att_uuid).expect("attachment");
        let _overview = _att.decrypt_overview().expect("decrypt overview");
        let _icon = _att.decrypt_icon().expect("decrypt icon");
        let _content = _att.decrypt_content().expect("decrypt content");

        for item in unlocked.get_items() {
            let _overview = item.overview().expect("overview");
            let _detail = item.detail().expect("detail");

            for att in item.get_attachments().expect("attachments") {
                let _overview = att.decrypt_overview().expect("decrypt overview");
                let _icon = att.decrypt_icon().expect("decrypt icon");
                let _content = att.decrypt_content().expect("decrypt content");
            }
        }
    }
}
