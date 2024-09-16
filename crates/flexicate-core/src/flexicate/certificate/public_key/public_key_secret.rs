

// public_key_secret

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
  PUBLICKEYTYPE_ED25519_001,
  SecretKeyData,
};


impl PublicKeyInfo {

  pub(
      in super::super
  ) fn sign_data_with_secret_key_to_bytes(
      &self,
      data: &[u8],
  ) -> Result<
      Vec<u8>,
      ErrorCertiflexicate,
  > {
    if let Some(secret_key_data) = &self.secret_key_data {
      secret_key_data.sign_data_to_bytes_signature(data)
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "secret key data not available",
      ))
    }
  }

  pub(
      in super::super
  ) fn sign_data_with_secret_key_to_base64(
      &self,
      data: &[u8],
  ) -> Result<
      String,
      ErrorCertiflexicate,
  > {
    if let Some(secret_key_data) = &self.secret_key_data {
      secret_key_data.sign_data_to_base64_encoded_signature(data)
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "secret key data is not available",
      ))
    }
  }

  pub(
      in super::super
  ) fn perhaps_add_secret_key_data(
      &mut self,
      secret_key_data: &[u8; 32],
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.secret_key_data.is_none() {
      if self.of_type == PUBLICKEYTYPE_ED25519_001 {
        if let Some(ref vk) = self.ed25519_public_key_data {
          let sk = SecretKeyData::get_new_checked_from_secret_data(
              secret_key_data,
              vk,
          )?;
          self.secret_key_data = Some(sk);
          if self.has_secret_key_data() {
            Ok(())
          } else {
            Err(ErrorCertiflexicate::attach_skey(
                "secret key attach failure",
            ))
          }
        } else {
          Err(ErrorCertiflexicate::attach_skey(
              "no verify key in public key",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::attach_skey(
            "unimplemented type",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::attach_skey(
          "secret key already attached",
      ))
    }
    
  }

  pub(
      in super::super
  ) fn get_secret_key_data_to_export(
      &self,
  ) -> Result<
      [u8; 32],
      ErrorCertiflexicate,
  > {
    if let Some(sk) = &self.secret_key_data {
      Ok(sk.export_secret_key_bytes_unencrypted())
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "secret key data not available is",
      ))
    }
  }

  pub(
      in super::super
  ) fn has_secret_key_data(
      &self,
  ) -> bool {
    self.secret_key_data.is_some()
  }

  pub(
      super
  ) fn clear_secret_key_data(
      &mut self,
  ) {
    if self.has_secret_key_data() {
      self.secret_key_data = None;
    };
  }

}

