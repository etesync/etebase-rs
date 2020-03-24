use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionInfo {
    #[serde(rename = "type")]
    pub col_type: String,
    pub display_name: String,
    pub description: Option<String>,
    pub color: Option<i32>,
}

pub const ACTION_ADD: &str = "ADD";
pub const ACTION_CHANGE: &str = "CHANGE";
pub const ACTION_DELETE: &str = "DELETE";

#[derive(Serialize, Deserialize)]
pub struct SyncEntry {
    pub action: String,
    pub content: String,
}
