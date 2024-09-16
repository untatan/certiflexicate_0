

// signatures_accepted_accessors

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
};


impl SignatureAccepted {

  pub(
      super
  ) fn get_signature_accepted_public_key_info_clone_clean(
      &self,
  ) -> Result<
      PublicKeyInfo,
      ErrorCertiflexicate,
  > {
    match self {
      SignatureAccepted::NotAccepted(
          sig
      ) => sig.get_sig_public_key_info_clone_clean(),
      SignatureAccepted::AcceptedSelf(
          sig
      ) => sig.get_sig_public_key_info_clone_clean(),
      SignatureAccepted::Accepted(
          sig
      ) => sig.get_sig_public_key_info_clone_clean(),
    }
  }

}

