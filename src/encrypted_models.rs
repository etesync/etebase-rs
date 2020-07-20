// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use serde::{Serialize, Deserialize};


#[derive(Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct CollectionSerialRead {
    pub accessLevel: String,
    #[serde(with = "serde_bytes")]
    pub collectionKey: Vec<u8>,
    pub stoken: Option<String>,
}

#[derive(Serialize, Clone)]
#[allow(non_snake_case)]
pub struct CollectionSerialWrite {
    pub accessLevel: String,
    pub stoken: Option<String>,
}


pub struct EncryptedCollection {
    pub access_level: String,
    pub collection_key: Vec<u8>,
    pub stoken: Option<String>,
}

impl EncryptedCollection {
    pub fn deserialize(serialized: CollectionSerialRead) -> Self {
        Self {
            access_level: serialized.accessLevel,
            collection_key: serialized.collectionKey,
            stoken: serialized.stoken,
        }
    }

    pub fn serialize(&self) -> CollectionSerialWrite {
        CollectionSerialWrite {
            accessLevel: self.access_level.to_owned(),
            stoken: self.stoken.clone(),
        }
    }
}
