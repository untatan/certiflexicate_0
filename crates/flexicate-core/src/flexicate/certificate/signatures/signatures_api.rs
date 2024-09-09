

// signatures_api


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



mod api_01 {

  use super::{
    super::{
      SignatureData,
    },
  };


  impl SignatureData {

    /// Get a reference to the nonce
    pub fn get_nonce(&self) -> &str {
      self.get_nonce_str()
    }

  }

}

