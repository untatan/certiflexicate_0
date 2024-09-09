

// public_key_deserialize

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
  PublicKeyInfo,
  PublicKeyInfoSerial,
};


impl TryFrom<PublicKeyInfoSerial> for PublicKeyInfo {

  type Error = ErrorCertiflexicate;

  fn try_from (
      pk: PublicKeyInfoSerial,
  ) -> Result<
      PublicKeyInfo,
      Self::Error,
  > {
    let mut public_signing_key = PublicKeyInfo
        ::get_public_key_info_by_serialized_values(
            pk.version,
            pk.of_type,
            pk.base64,
            pk.identifier,
        )
    ;
    public_signing_key.update_is_not_useable()?;
    public_signing_key.seems_valid_minimum()?;
    Ok(public_signing_key)
  }

}

