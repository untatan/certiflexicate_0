

// signatures_accepted_api


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
      SignatureAccepted,
      super::{
        PublicKeyInfo,
        super::{
          super::{
            error::{
              ErrorCertiflexicate,
            },
          },
        },
      },
    },
  };


  impl SignatureAccepted {

    /// Get the PublicKeyInfo from the wrapped SignatureData
    pub fn get_signature_public_key_info(
        &self,
    ) -> Result<
        PublicKeyInfo,
        ErrorCertiflexicate,
    > {
      self.get_signature_accepted_public_key_info_clone_clean()
    }

  }

}

