

// signatures_deserialize

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
    error::{
      ErrorCertiflexicate,
    },
  },
};

use super::{
  SignatureData,
  SignatureDataSerial,
};


impl TryFrom<SignatureDataSerial> for SignatureData {

  type Error = ErrorCertiflexicate;
  
  fn try_from (
      sig: SignatureDataSerial,
  ) -> Result<
      SignatureData,
      Self::Error,
  > {
    let mut signature = SignatureData::get_new_from_serial_values(
        sig.version,
        sig.base64,
        sig.nonce,
        sig.identifier,
        sig.comment,
        sig.start_date,
        sig.stop_date,
        sig.signed_fields,
        sig.accepted_base64,
        sig.public_signing_key,
    );
    signature.seems_valid_wo_nonce_and_wo_public_key(&None)?;
    Ok(signature)
  }

}

