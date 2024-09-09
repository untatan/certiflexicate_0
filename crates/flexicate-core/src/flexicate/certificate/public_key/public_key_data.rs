

// public_key_data

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
    helpers::{
      base64::{
        get_base64_decoded,
      },
    },
  },
};

use super::{
  PublicKeyInfo,
};


impl PublicKeyInfo {

  pub(
      in super::super
  ) fn get_public_key_data_to_sign(
      &self
  ) -> Result<
      Vec<Vec<u8>>,
      ErrorCertiflexicate,
  > {
    let pk = get_base64_decoded(
        &self.base64,
    )?;
    let mut v1 = Vec::new();
    for item in (self.of_type.len() as u64).to_le_bytes() {
      v1.push(item);
    };
    for item in self.of_type.as_bytes() {
      v1.push(*item);
    };
    let mut v2 = Vec::new();
    for item in (self.identifier.len() as u64).to_le_bytes() {
      v2.push(item);
    };
    for item in self.identifier.as_bytes() {
      v2.push(*item);
    };
    let v = vec![
        self.version.to_le_bytes().as_slice().to_vec(),
        v1,
        v2,
        pk,
    ];
    Ok(v)
  }

}

