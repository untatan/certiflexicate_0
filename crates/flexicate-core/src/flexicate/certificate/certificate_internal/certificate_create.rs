

// certificate_create

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



use std::{
  collections::HashMap as std_collections_HashMap,
};

use super::{
  Certiflexicate,
  CERTIFLEXICATEIDENTIFIER,
  ErrorCertiflexicate,
  PublicKeyInfo,
  SignatureData,
  super::{
    version::{
      LASTVERSION,
    },
  },
};


impl Certiflexicate {

  pub(
      in super::super
  ) fn get_defaults() -> Certiflexicate {
    Certiflexicate {
      certiflexicate: "".to_string(),
      version: 0,
      byte_content: None,
      public_key_info: None,
      signatures: None,
      all_signatures_visited_once: false,
      regexes: None,
    }
  }

  pub(
      in super::super
  ) fn new_current() -> Certiflexicate {
    let mut cert = Certiflexicate::get_defaults();
    cert.certiflexicate = CERTIFLEXICATEIDENTIFIER.to_string();
    cert.version = LASTVERSION;
    cert
  }

  fn new_current_with_new_public_key(
      secret_key_data: Option<&[u8; 32]>,
  ) -> Certiflexicate {
    let mut cert = Certiflexicate::new_current();
    let pk = if let Some(secret_data) = secret_key_data {
      PublicKeyInfo::new_with_existing_secret_key(secret_data)
    } else {
      PublicKeyInfo::new_with_new_secret_key()
    };
    cert.public_key_info = Some(pk);
    cert
  }

  pub(
      in super::super
  ) fn new_current_with_new_keys_self_signed(
      secret_key_data: Option<&[u8; 32]>,
  ) -> Result<
      (
          Certiflexicate,
          [u8; 32],
      ),
      ErrorCertiflexicate,
  > {
    let mut cert = Certiflexicate::new_current_with_new_public_key(
        secret_key_data,
    );
    let signature = SignatureData::create_first_self_signed_public_key(
        &cert,
    )?;
    let mut signatures = std_collections_HashMap::new();
    signatures.insert(
        signature.get_nonce_string(),
        signature,
    );
    cert.signatures = Some(signatures);
    if let Some(ref pk) = cert.public_key_info {
      let sk = pk.get_secret_key_data_to_export()?;
      Ok((cert, sk))
    } else {
      Err(ErrorCertiflexicate::create_cert(
          "no public key",
      ))
    }
  }

}



#[cfg(test)]
mod tests {

  use super::{
    Certiflexicate,
  };


  #[test]
  fn certificate_with_public_key_new_001() {
    let c = Certiflexicate::new_current_with_new_public_key(None);
    assert!(c.public_key_info.is_some())
  }

}

