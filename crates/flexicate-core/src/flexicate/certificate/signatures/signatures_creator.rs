

// signatures_creator

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



use crate::{
  flexicate::{
    helpers::{
      random::{
        get_random_bytes_as_string,
      },
    },
  },
};

use super::{
  AcceptState,
  LASTSIGNATURESVERSION,
  PublicKeyInfo,
  SignatureData,
  VerifyState,
};


impl SignatureData {

  fn new(
  ) -> SignatureData {
    SignatureData {
      version: LASTSIGNATURESVERSION,
      base64: "".to_string(),
      nonce: "".to_string(),
      identifier: "".to_string(),
      comment: "".to_string(),
      start_date: "".to_string(),
      stop_date: "".to_string(),
      signed_fields: Vec::with_capacity(0),
      accepted_base64: "".to_string(),
      public_sig_key_info: None,
      datetime_start: None,
      datetime_stop: None,
      claimed_signed_fields: Vec::new(),
      verified_signed_fields: Vec::new(),
      claimed_self_signature: false,
      self_signed: false,
      verify_state: VerifyState::get_default(),
      accept_state: AcceptState::get_default(),
      cert_has_same_public_key: false,
      is_isolated_clone: false,
    }
  }

}


impl SignatureData {

  pub(super) fn new_current_default_from_public_key(
      pk: PublicKeyInfo,
  ) -> SignatureData {
    let mut sig = SignatureData::new();
    sig.public_sig_key_info = Some(pk);
    sig.nonce = get_random_bytes_as_string(36);
    sig.claimed_self_signature = true;
    sig.cert_has_same_public_key = true;
    sig
  }

  pub(super) fn new_current_default_general_with_public_key(
      pk: PublicKeyInfo,
      nonce: String,
      self_signed: bool,
  ) -> SignatureData {
    let mut sig = SignatureData::new();
    sig.public_sig_key_info = Some(pk);
    sig.nonce = nonce;
    if self_signed {
      sig.claimed_self_signature = self_signed;
      sig.cert_has_same_public_key = true;
    };
    sig
  }

  pub(super) fn get_new_from_serial_values(
      version: u32,
      base64: String,
      nonce: String,
      identifier: String,
      comment: String,
      start_date: String,
      stop_date: String,
      signed_fields: Vec<String>,
      accepted_base64: String,
      pk: PublicKeyInfo,
  ) -> SignatureData {
    let mut sig = SignatureData::new();
    sig.version = version;
    sig.base64 = base64;
    sig.nonce = nonce;
    sig.identifier = identifier;
    sig.comment = comment;
    sig.start_date = start_date;
    sig.stop_date = stop_date;
    sig.signed_fields = signed_fields;
    sig.accepted_base64 = accepted_base64;
    if !pk.is_not_useable() {
      sig.public_sig_key_info = Some(pk);
    };
    sig
  }

}

