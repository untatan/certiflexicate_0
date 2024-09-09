

// public_key_info

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



use super::{
  PublicKeyInfo,
};


impl PublicKeyInfo {

  pub(
      in super::super
  ) fn is_not_useable(&self) -> bool {
    self.not_useable
  }

  //∵ to be used
  #[allow(dead_code)]
  pub(
      in super::super
  ) fn get_base64(&self) -> String {
    self.base64.clone()
  }

  #[allow(clippy::needless_bool)]
  pub(
      in super::super
  ) fn equal_wo_keys_data(
      &self,
      other: &PublicKeyInfo,
  ) -> bool {
    if self.version == other.version
        && self.of_type == other.of_type
        && self.base64 == other.base64
        && self.identifier == other.identifier
        && self.not_useable == other.not_useable
    {
      true
    } else {
      false
    }
  }

}

