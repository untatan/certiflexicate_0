

// certificate_serial

// Copyright (C) 2024 untatan

// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.



use std::{
  collections::HashMap as std_collections_HashMap,
};

use serde::{
  Deserialize,
  Serialize,
};

use super::{
  Certiflexicate,
  PublicKeyInfo,
  SignatureData,
};


#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(
  in super::super
) struct CertiflexicateSerial {
  pub(super) certiflexicate: String,
  pub(super) version: u32,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  #[serde(default = "Vec::new")]
  pub(super) byte_content: Vec<u8>,
  #[serde(skip_serializing_if = "PublicKeyInfo::is_not_useable")]
  #[serde(default = "PublicKeyInfo::get_not_useable_default")]
  pub(super) public_signing_key: PublicKeyInfo,
  #[serde(skip_serializing_if = "std_collections_HashMap::is_empty")]
  #[serde(default = "std_collections_HashMap::new")]
  pub(super) signatures: std_collections_HashMap<
      String,
      SignatureData,
  >,
}


impl From<Certiflexicate> for CertiflexicateSerial {

  fn from (c: Certiflexicate) -> CertiflexicateSerial {

    let public_signing_key = if let Some(
        pk
    ) = c.public_key_info {
      pk
    } else {
      PublicKeyInfo::get_not_useable_default()
    };

    let signatures = if let Some(
        sig
    ) = c.signatures {
      sig
    } else {
      std_collections_HashMap::with_capacity(0)
    };

    let byte_content = if let Some(
        bc
    ) = c.byte_content {
      bc
    } else {
      Vec::with_capacity(0)
    };

    CertiflexicateSerial {
      certiflexicate: c.certiflexicate,
      version: c.version,
      byte_content: byte_content,
      public_signing_key: public_signing_key,
      signatures: signatures,
    }
  }

}

