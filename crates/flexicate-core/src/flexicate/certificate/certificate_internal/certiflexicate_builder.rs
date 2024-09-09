

// certiflexicate_builder

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
  DataContent,
  ErrorCertiflexicate,
  PublicKeyInfo,
  SignatureData,
  certificate_serial::{
    CertiflexicateSerial,
  },
  super::{
    signatures::{
      signatures_validator::{
        check_if_nonce_valid,
      },
    },
    version::{
      LASTVERSION,
      check_if_valid_version,
    },
  },
};


/// Construct a `Certiflexicate` from its parts.
/// 
/// If a `Certiflexicate` is not loaded by Deserialization as a whole,
/// it may be possible to create it partially with this build.
///
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CertiflexicateBuilder {
  certiflexicate: String,
  version: u32,
  byte_content: Option<Vec<u8>>,
  public_signing_key: Option<PublicKeyInfo>,
  signatures: std_collections_HashMap<
      String,
      SignatureData,
  >,
}


impl CertiflexicateBuilder {

  fn new() -> CertiflexicateBuilder {
    CertiflexicateBuilder {
      certiflexicate: CERTIFLEXICATEIDENTIFIER.to_string(),
      version: LASTVERSION,
      byte_content: None,
      public_signing_key: None,
      signatures: std_collections_HashMap::new(),
    }
  }

}


impl CertiflexicateBuilder {

  /// Initiates the `CertiflexicateBuilder`.
  ///
  /// An empty `version` uses the current default.
  pub fn new_from_version(
      version: Option<u32>,
  ) -> Result<
      CertiflexicateBuilder,
      ErrorCertiflexicate,
  > {
    let mut builder = CertiflexicateBuilder::new();
    if let Some(ver) = version {
      check_if_valid_version(ver)?;
      builder.version = ver;
      Ok(builder)
    } else {
      Ok(builder)
    }
  }

  /// Adds `DataContent` for each field once.
  pub fn add_data(
      &mut self,
      data: DataContent,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    match data {
      DataContent::Bytes(v) => {
        if self.byte_content.is_some() {
          Err(ErrorCertiflexicate::building(
              "existing bytes",
          ))
        } else if v.is_empty() {
          Err(ErrorCertiflexicate::building(
              "no bytes provided",
          ))
        } else {
          self.byte_content = Some(v);
          Ok(())
        }
      }
    }
  }

  /// Adds the `PublicKeyInfo` once.
  pub fn add_public_key(
      &mut self,
      public_key: PublicKeyInfo,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let pk = public_key.clone();
    if self.public_signing_key.is_none() {
      public_key.seems_valid_minimum()?;
      self.public_signing_key = Some(pk);
      Ok(())
    } else {
      Err(ErrorCertiflexicate::building(
          "public key previously added",
      ))
    }
  }

  /// Adds `SignatureData` multiple times.
  pub fn add_signature(
      &mut self,
      signature: SignatureData,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let mut sig = signature.clone();
    let nonce = sig.get_nonce_string();
    check_if_nonce_valid(&nonce)?;
    if self.public_signing_key.is_some() {
      #[allow(clippy::map_entry)]
      if self.signatures.contains_key(&nonce) {
        Err(ErrorCertiflexicate::building(
            "signature perhaps previously added",
        ))
      } else {
        sig.seems_valid_wo_nonce(&self.public_signing_key)?;
        self.signatures.insert(nonce, signature);
        Ok(())
      }
    } else {
      Err(ErrorCertiflexicate::building(
          "add the public key first",
      ))
    }
  }

  /// The last step tries to create a `Certiflexicate`.
  pub fn build(
      &self,
  ) -> Result<
      Certiflexicate,
      ErrorCertiflexicate,
  > {
    if let Some(pk) = &self.public_signing_key {
      if !self.signatures.is_empty() {
        let byte_content = if let Some(
            bc
        ) = &self.byte_content {
          bc.clone()
        } else {
          Vec::with_capacity(0)
        };
        Certiflexicate::try_from(
            CertiflexicateSerial {
              certiflexicate: self.certiflexicate.clone(),
              version: self.version,
              byte_content: byte_content,
              public_signing_key: pk.clone(),
              signatures: self.signatures.clone(),
            }
        )
      } else {
        Err(ErrorCertiflexicate::building(
            "missing signatures",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::building(
          "missing public key",
      ))
    }
  }

}

