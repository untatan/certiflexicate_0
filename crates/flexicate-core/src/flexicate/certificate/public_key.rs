

// public_key

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



use serde::{Deserialize, Serialize};

use ed25519_dalek::{
  VerifyingKey as ed25519_dalek_VerifyingKey,
};

use super::{
  secret_key::{
    SecretKeyData,
  },
};


mod public_key_create;
mod public_key_data;
mod public_key_info;
mod public_key_secret;
mod public_key_serial;
mod public_key_deserialize;
mod public_key_validate;
mod public_key_verify;


use public_key_serial::{
  PublicKeyInfoSerial,
};


const LASTPUBLICKEYVERSION: u32 = 1;

const KNOWNPUBLICKEYVERSIONS: [u32; 1] = [1];

const DEPRECATEDPUBLICKEYVERSIONS: [u32; 0] = [];

const PUBLICKEYTYPE_ED25519_001: &str = "ed25519_1";

const KNOWNPUBLICKEYTYPES: [&str; 1] = [PUBLICKEYTYPE_ED25519_001];


/// Each public key is embeded with other information in `PublicKeyInfo`.
///
/// It is an essential part of each `Certiflexicate`
/// and foreign `SignatureData`.
#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default = "PublicKeyInfo::get_not_useable_default")]
#[serde(try_from = "PublicKeyInfoSerial")]
#[serde(into = "PublicKeyInfoSerial")]
pub struct PublicKeyInfo {
  version: u32,
  of_type: String,
  base64: String,
  identifier: String,
  #[serde(skip)]
  not_useable: bool,
  #[serde(skip)]
  secret_key_data: Option<SecretKeyData>,
  #[serde(skip)]
  ed25519_public_key_data: Option<ed25519_dalek_VerifyingKey>,
}


impl PartialEq for PublicKeyInfo {

  fn eq(&self, other: &PublicKeyInfo) -> bool {
    self.equal_wo_keys_data(other)
  }

}

