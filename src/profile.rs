// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64;
use serde_json;

use secstr::SecStr;

use Result;

/// The profile data from the file, the names match the keys in the file.
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct ProfileData {
    pub lastUpdatedBy: String,
    pub updatedAt: i64,
    pub profileName: String,
    pub salt: SecStr,
    pub passwordHint: Option<String>,
    pub masterKey: SecStr,
    pub iterations: u64,
    pub uuid: String,
    pub overviewKey: SecStr,
    pub createdAt: i64,
}

/// The information for a particular profile. This includes the encrypted master
/// and overview keys, which are used to decrypt the details and superficial
/// information respectively.
#[derive(Debug)]
pub struct Profile {
    pub last_updated_by: String,
    pub updated_at: i64,
    pub profile_name: String,
    pub salt: SecStr,
    pub password_hint: Option<String>,
    pub master_key: SecStr,
    pub iterations: u64,
    pub uuid: String,
    pub overview_key: SecStr,
    pub created_at: i64,
}

impl Profile {
    fn from_profile_data(d: ProfileData) -> Result<Profile> {
        let salt = SecStr::new(base64::decode(d.salt.unsecure())?);
        let master_key = SecStr::new(base64::decode(&d.masterKey.unsecure())?);
        let overview_key = SecStr::new(base64::decode(&d.overviewKey.unsecure())?);

        Ok(Profile {
            last_updated_by: d.lastUpdatedBy,
            updated_at: d.updatedAt,
            profile_name: d.profileName,
            password_hint: d.passwordHint,
            iterations: d.iterations,
            uuid: d.uuid,
            created_at: d.createdAt,
            salt,
            master_key,
            overview_key,
        })
    }
}

// Read in the profile. If the user's master password is given, we also decrypt the master and overview keys
pub fn read_profile(p: &Path) -> Result<Profile> {
    let mut f = File::open(p)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("var profile=").trim_right_matches(';');
    let profile_data: ProfileData = serde_json::from_str(json_str)?;

    Profile::from_profile_data(profile_data)
}
