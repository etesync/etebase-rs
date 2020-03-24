use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionInfo {
    #[serde(rename = "type")]
    col_type: String,
    display_name: String,
    description: Option<String>,
    color: Option<i32>,
}

pub const ACTION_ADD: &str = "ADD";
pub const ACTION_CHANGE: &str = "CHANGE";
pub const ACTION_DELETE: &str = "DELETE";

#[derive(Serialize, Deserialize)]
pub struct SyncEntry {
    action: String,
    content: String,
}
