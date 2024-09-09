

// signatures

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



use chrono::{
  DateTime as chrono_DateTime,
  offset::{
    Utc as chrono_offset_Utc,
  },
};

use serde::{
  Deserialize,
  Serialize,
};

use super::{
  Certiflexicate,
  public_key::{
    PublicKeyInfo,
  },
  signature_fields::{
    CertiflexicateFieldTypes,
  },
};

pub(super) mod signatures_accepted;
pub(super) mod signatures_signable_data;
pub(super) mod signatures_validator;
pub(super) mod signatures_verify_states;

mod signatures_accept_states;
mod signatures_api;
mod signatures_data_collector;
mod signatures_creator;
mod signatures_deserialize;
mod signatures_serial;
mod signatures_signator;
mod signatures_values_getters_setters;
mod signatures_verificator;


use signatures_verify_states::{
  VerifyState,
};

use signatures_accept_states::{
  AcceptState,
};

use signatures_serial::{
  SignatureDataSerial,
};


const LASTSIGNATURESVERSION: u32 = 1;

const KNOWNSIGNATURESVERSIONS: [u32; 1] = [1];

const DEPRECATEDSIGNATUREVERSIONS: [u32; 0] = [];


/// Each signature is embeded with other information
/// in a `SignatureData` structure.
///
/// A `Certiflexicate` can have multiple signatures created with the secret
/// part corresponding to the public key in this certiflexicate (self signed)
/// or with the keys from other certiflexicates.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SignatureDataSerial")]
#[serde(into = "SignatureDataSerial")]
pub struct SignatureData {
  version: u32,
  base64: String,
  nonce: String,
  identifier: String,
  comment: String,
  start_date: String,
  stop_date: String,
  signed_fields: Vec<String>,
  accepted_base64: String,
  public_sig_key_info: Option<PublicKeyInfo>,
  #[serde(skip)]
  #[serde(default = "get_empty_datetime_opt_none")]
  datetime_start: Option<chrono_DateTime<chrono_offset_Utc>>,
  #[serde(skip)]
  #[serde(default = "get_empty_datetime_opt_none")]
  datetime_stop: Option<chrono_DateTime<chrono_offset_Utc>>,
  #[serde(skip)]
  #[serde(default = "Vec::new")]
  claimed_signed_fields: Vec<CertiflexicateFieldTypes>,
  #[serde(skip)]
  #[serde(default = "Vec::new")]
  verified_signed_fields: Vec<CertiflexicateFieldTypes>,
  #[serde(skip)]
  #[serde(default = "get_false")]
  claimed_self_signature: bool,
  #[serde(skip)]
  #[serde(default = "get_false")]
  self_signed: bool,
  #[serde(skip)]
  #[serde(default = "VerifyState::get_default")]
  verify_state: VerifyState,
  #[serde(skip)]
  #[serde(default = "AcceptState::get_default")]
  accept_state: AcceptState,
  #[serde(skip)]
  #[serde(default = "get_false")]
  cert_has_same_public_key: bool,
  #[serde(skip)]
  #[serde(default = "get_false")]
  is_isolated_clone: bool,
}

