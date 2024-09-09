

// public_key_create

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
    helpers::{
      random::{
        get_random_bytes_as_string,
      },
    },
  },
};

use super::{
  LASTPUBLICKEYVERSION,
  PublicKeyInfo,
  PUBLICKEYTYPE_ED25519_001,
  SecretKeyData,
};


impl PublicKeyInfo {

  fn new_from_secret_key(
      sk: SecretKeyData,
  ) -> PublicKeyInfo {
    let vk = sk.get_public_key();
    PublicKeyInfo {
      version: LASTPUBLICKEYVERSION,
      of_type: PUBLICKEYTYPE_ED25519_001.to_string(),
      base64: sk.get_base64_encoded_public_key(),
      identifier: get_random_bytes_as_string(36),
      not_useable: false,
      secret_key_data: Some(sk),
      ed25519_public_key_data: Some(vk),
    }
  }

}


impl PublicKeyInfo {
  
  pub(
      in super::super
  ) fn new_with_new_secret_key() -> PublicKeyInfo {
    PublicKeyInfo::new_from_secret_key(SecretKeyData::new())
  }

  pub(
      in super::super
  ) fn new_with_existing_secret_key(
      skd: &[u8; 32],
  ) -> PublicKeyInfo {
    PublicKeyInfo::new_from_secret_key(
        SecretKeyData::get_new_from_existing_secret_data(
            skd,
        ),
    )
  }

  pub(
      in super::super
  ) fn get_not_useable_default() -> PublicKeyInfo {
    PublicKeyInfo {
      version: 0,
      of_type: "".to_string(),
      base64: "".to_string(),
      identifier: "".to_string(),
      not_useable: true,
      secret_key_data: None,
      ed25519_public_key_data: None,
    }
  }

  pub(
      super
  ) fn get_public_key_info_by_serialized_values(
      version: u32,
      of_type: String,
      base64: String,
      identifier: String,
  ) -> PublicKeyInfo {
    PublicKeyInfo {
      version: version,
      of_type: of_type,
      base64: base64,
      identifier: identifier,
      not_useable: true,
      secret_key_data: None,
      ed25519_public_key_data: None,
    }
  }

}

