

// public_key_serial

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



use serde::{
  Deserialize,
  Serialize,
};

use super::{
  PublicKeyInfo,
};


#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct PublicKeyInfoSerial {
  pub(super) version: u32,
  pub(super) of_type: String,
  pub(super) base64: String,
  pub(super) identifier: String,
}


impl From<PublicKeyInfo> for PublicKeyInfoSerial {

  fn from (pk: PublicKeyInfo) -> PublicKeyInfoSerial {
    PublicKeyInfoSerial {
      version: pk.version,
      of_type: pk.of_type,
      base64: pk.base64,
      identifier: pk.identifier,
    }
  }

}

