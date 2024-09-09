

// public_key_verify

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



use ed25519_dalek::{
  Signature as ed25519_dalek_Signature,
};

use super::{
  PublicKeyInfo,
  public_key_validate::{
    check_if_edwardspoint,
  },
  super::{
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
  },
};


impl PublicKeyInfo {

  pub(
      in super::super
  ) fn verify_data_signed_with_public_key(
      &self,
      data: &[u8],
      signature: &[u8],
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if let Some(vk) = self.ed25519_public_key_data {
      //∵ TODO check if signature valid bytes
      let sig = ed25519_dalek_Signature::from_slice(signature)
          .map_err(|e| ErrorCertiflexicate::ed25519_err(
              &e.to_string(),
          ))
      ?;
      check_if_edwardspoint(sig.r_bytes())?;
      vk.verify_strict(data, &sig).map_err(
          |e| ErrorCertiflexicate::ed25519_err(
              &e.to_string(),
          )
      )
    } else {
      Err(ErrorCertiflexicate::verify_sig_err(
          "no public key data",
      ))
    }
  }

}

