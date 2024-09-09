

// secret_key

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



use std::fmt;

use ed25519_dalek::{
  SigningKey as ed25519_dalek_SigningKey,
};


mod secret_key_operations;


#[non_exhaustive]
#[derive(Clone, PartialEq)]
pub(super) struct SecretKeyData {
  signing_key: ed25519_dalek_SigningKey,
}


impl fmt::Debug for SecretKeyData {

  #[cfg(not(test))]
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SecretKeyData")
      .field("signing_key", &"keys hidden in debug output")
      .finish()
  }
  
  #[cfg(test)]
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SecretKeyData")
      .field("signing_key", &self.signing_key)
      .finish()
  }
}

