// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use base64;
use secstr::SecStr;
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::rc::Rc;

use {opdata01, OverviewKey, Result, Uuid};

#[derive(Debug, Deserialize)]
pub struct FolderData {
    pub created: i64,
    pub overview: SecStr,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    #[serde(default)]
    pub smart: bool,
}

/// A "folder" or named group of items.
#[derive(Debug)]
pub struct Folder {
    pub created: i64,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    pub smart: bool,
    overview: SecStr,
    overview_key: Rc<OverviewKey>,
}

impl Folder {
    fn from_folder_data(d: FolderData, overview_key: Rc<OverviewKey>) -> Result<Folder> {
        Ok(Folder {
            created: d.created,
            overview: SecStr::new(base64::decode(d.overview.unsecure())?),
            tx: d.tx,
            updated: d.updated,
            uuid: d.uuid,
            smart: d.smart,
            overview_key,
        })
    }

    /// Decrypt the folder's overview data
    pub fn overview(&self) -> Result<Overview> {
        let raw = opdata01::decrypt(&self.overview, &self.overview_key)?;
        Ok(Overview::from_slice(&raw)?)
    }
}

/// Read the encrypted folder data
pub fn read_folders(p: &Path, overview_key: &Rc<OverviewKey>) -> Result<HashMap<Uuid, Folder>> {
    let mut f = match File::open(p) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e.into()),
    };

    let mut s = String::new();
    f.read_to_string(&mut s)?;
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("loadFolders(").trim_right_matches(");");
    let mut folder_datas: HashMap<Uuid, FolderData> = serde_json::from_str(json_str)?;
    let mut folders = HashMap::new();

    for (k, v) in folder_datas.drain() {
        folders.insert(k, Folder::from_folder_data(v, overview_key.clone())?);
    }

    Ok(folders)
}

#[derive(Debug, Deserialize)]
pub struct Overview {
    pub title: SecStr,
    // Smart folders have a predicate, but the one from the sample set contains
    // some invalid text, and it decodes into binary anyway.
    // #[serde(rename = "predicate_b64", deserialize_with = "base64_deser")]
    // pub predicate: Vec<u8>,
}

impl Overview {
    pub fn from_slice(d: &SecStr) -> serde_json::Result<Overview> {
        serde_json::from_slice(d.unsecure())
    }
}
