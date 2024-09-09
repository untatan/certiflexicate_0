

// signatures_serial

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

use crate::{
  flexicate::{
    helpers::{
      get_default_values::{
        is_empty_string,
        get_empty_string,
      },
      
    },
  },
};

use super::{
  PublicKeyInfo,
  SignatureData,
};


#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SignatureDataSerial {
  pub(super) version: u32,
  pub(super) base64: String,
  #[serde(skip_serializing_if = "is_empty_string")]
  #[serde(default = "get_empty_string")]
  pub(super) nonce: String,
  #[serde(skip_serializing_if = "is_empty_string")]
  #[serde(default = "get_empty_string")]
  pub(super) identifier: String,
  #[serde(skip_serializing_if = "is_empty_string")]
  #[serde(default = "get_empty_string")]
  pub(super) comment: String,
  #[serde(skip_serializing_if = "is_empty_string")]
  #[serde(default = "get_empty_string")]
  pub(super) start_date: String,
  #[serde(skip_serializing_if = "is_empty_string")]
  #[serde(default = "get_empty_string")]
  pub(super) stop_date: String,
  pub(super) signed_fields: Vec<String>,
  #[serde(skip_serializing_if = "is_empty_string")]
  #[serde(default = "get_empty_string")]
  pub(super) accepted_base64: String,
  #[serde(skip_serializing_if = "PublicKeyInfo::is_not_useable")]
  #[serde(default = "PublicKeyInfo::get_not_useable_default")]
  pub(super) public_signing_key: PublicKeyInfo,
}


impl From<SignatureData> for SignatureDataSerial {

  fn from (sig: SignatureData) -> SignatureDataSerial {
    let pubkey = if let Some(pk) = sig.public_sig_key_info {
      if sig.cert_has_same_public_key && !sig.is_isolated_clone {
        PublicKeyInfo::get_not_useable_default()
      } else {
        pk
      }
    } else {
      PublicKeyInfo::get_not_useable_default()
    };
    SignatureDataSerial {
      version: sig.version,
      base64: sig.base64,
      nonce: sig.nonce,
      identifier: sig.identifier,
      comment: sig.comment,
      start_date: sig.start_date,
      stop_date: sig.stop_date,
      signed_fields: sig.signed_fields,
      accepted_base64: sig.accepted_base64,
      public_signing_key: pubkey,
    }
  }

}

