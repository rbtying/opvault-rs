use serde_json as json;

use secstr::SecStr;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub title: Option<SecStr>,
    pub ainfo: Option<SecStr>,
    #[serde(rename = "URLs", default)]
    pub urls: Vec<URL>,
    pub url: Option<SecStr>,
    #[serde(default)]
    pub tags: Vec<SecStr>,
    pub ps: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct URL {
    pub u: SecStr,
}

impl Overview {
    // Parse an overview object from a JSON slice
    pub fn from_slice(s: &SecStr) -> json::Result<Self> {
        json::from_slice(s.unsecure())
    }
}
