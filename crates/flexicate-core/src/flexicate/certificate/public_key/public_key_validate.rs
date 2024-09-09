

// public_key_validate

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



use curve25519_dalek::{
  edwards::{
    CompressedEdwardsY as curve25519_dalek_edwards_CompressedEdwardsY,
  },
};

use ed25519_dalek::{
  PUBLIC_KEY_LENGTH as ed25519_dalek_PUBLIC_KEY_LENGTH,
  VerifyingKey as ed25519_dalek_VerifyingKey,
};

use crate::{
  flexicate::{
    error::{
     ErrorCertiflexicate,
    },
    helpers::{
      base64::{
        all_chars_urlsafe,
        get_base64_decoded,
      },
    },
  },
};

use super::{
  DEPRECATEDPUBLICKEYVERSIONS,
  LASTPUBLICKEYVERSION,
  KNOWNPUBLICKEYVERSIONS,
  KNOWNPUBLICKEYTYPES,
  PublicKeyInfo,
};


const PUBLICKEY_BASE64_LENGTH: usize = 44;


impl PublicKeyInfo {

  fn check_pk_version(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.version > 0 {
      if self.version <= LASTPUBLICKEYVERSION {
        if KNOWNPUBLICKEYVERSIONS.contains(&self.version) {
          if !DEPRECATEDPUBLICKEYVERSIONS.contains(&self.version) {
            Ok(())
          } else {
            Err(ErrorCertiflexicate::invalid_pk_err("deprecated version"))
          }
        } else {
          Err(ErrorCertiflexicate::invalid_pk_err("unknown version"))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_pk_err("high version"))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_pk_err("low version"))
    }
  }

  fn check_pk_type(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if KNOWNPUBLICKEYTYPES.contains(&self.of_type.as_str()) {
      Ok(())
    } else {
      Err(ErrorCertiflexicate::invalid_pk_err("unknown type"))
    }
  }

  fn check_pk_base64(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if !self.base64.is_empty() {
      if self.base64.len() == PUBLICKEY_BASE64_LENGTH {
        if all_chars_urlsafe(
            &self.base64,
        ) {
          Ok(())
        } else {
          Err(ErrorCertiflexicate::invalid_pk_err(
              "public key base64 invalid char",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_pk_err(
            "public key base64 length",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_pk_err(
          "no public key",
      ))
    }
  }

  fn check_pk_identifier(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if !self.identifier.is_empty() {
      Ok(())
    } else {
      Err(ErrorCertiflexicate::invalid_pk_err(
          "no identifier",
      ))
    }
  }

  fn seems_valid_minimum_wo_useable(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.check_pk_version()?;
    self.check_pk_type()?;
    self.check_pk_base64()?;
    self.check_pk_identifier()
    // TODO more checks
  }

}


impl PublicKeyInfo {

  fn assign_public_key_data(
      &mut self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.ed25519_public_key_data.is_none() {
      if let Some(sk) = &self.secret_key_data {
        self.ed25519_public_key_data = Some(sk.get_public_key());
      } else {
        let pk = get_base64_decoded(&self.base64)?;
        if let Ok(
            ar
        ) = <[u8; ed25519_dalek_PUBLIC_KEY_LENGTH]>::try_from(pk) {
          check_if_edwardspoint(&ar)?;
          if let Ok(vk) = ed25519_dalek_VerifyingKey::from_bytes(&ar) {
            if !vk.is_weak() {
              self.ed25519_public_key_data = Some(vk);
            };
          };
        };
      };
    };
    if self.ed25519_public_key_data.is_some() {
      Ok(())
    } else {
      Err(ErrorCertiflexicate::invalid_pk_err(
          "valid public key data missing",
      ))
    }
  }

}


impl PublicKeyInfo {

  pub(
      in super::super
  ) fn seems_valid_minimum(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.seems_valid_minimum_wo_useable()?;
    if !self.is_not_useable() {
      Ok(())
    } else {
      Err(ErrorCertiflexicate::invalid_pk_err(
          "not useable",
      ))
    }
  }

  pub(super) fn update_is_not_useable(
      &mut self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.is_not_useable() {
      self.seems_valid_minimum_wo_useable()?;
      self.assign_public_key_data()?;
      self.not_useable = false;
    };
    Ok(())
  }

}


pub(super) fn check_if_edwardspoint(
    b: &[u8; ed25519_dalek_PUBLIC_KEY_LENGTH],
) -> Result<
    (),
    ErrorCertiflexicate,
> {
  let epc = curve25519_dalek_edwards_CompressedEdwardsY
      ::from_slice(
          b,
      ).map_err(|e| ErrorCertiflexicate::ed25519_err(
          &e.to_string(),
      ))
  ?;
  if epc.decompress().is_none() {
    Err(ErrorCertiflexicate::catch_err(
        "edwardspoint decompress",
    ))
  } else {
    Ok(())
  }
}



#[cfg(test)]
mod tests {

  use super::{
    check_if_edwardspoint,
  };


  const PUBLIC_TEST_KEY_BYTES: [u8; 32] = [
      34, 48, 254, 242, 196, 227, 191, 235, 37, 59,
      174, 83, 151, 73, 81, 247, 27, 103, 45, 246,
      36, 73, 69, 137, 135, 105, 97, 8, 239, 77,
      159, 28,
  ];


  #[test]
  fn bytes_are_public_key_suc_001() {
    let res = check_if_edwardspoint(&PUBLIC_TEST_KEY_BYTES);
    assert!(res.is_ok())
  }

  #[test]
  fn bytes_are_public_key_fail_001() {
    let public_test_key_bytes = PUBLIC_TEST_KEY_BYTES.map(
        |x| {
          if x == 34 {
            32
          } else {
            x
          }
        }
    );
    let res = check_if_edwardspoint(&public_test_key_bytes);
    assert!(res.is_err())
  }

  #[test]
  fn bytes_are_public_key_fail_002() {
    let public_test_key_bytes = PUBLIC_TEST_KEY_BYTES.map(
        |x| {
          if x == 34 {
            36
          } else {
            x
          }
        }
    );
    let res = check_if_edwardspoint(&public_test_key_bytes);
    assert!(res.is_err())
  }

  #[test]
  fn bytes_are_public_key_fail_003() {
    let public_test_key_bytes = PUBLIC_TEST_KEY_BYTES.map(
        |x| {
          if x == 73 {
            71
          } else {
            x
          }
        }
    );
    let res = check_if_edwardspoint(&public_test_key_bytes);
    assert!(res.is_err())
  }

  #[test]
  fn bytes_are_public_key_fail_004() {
    let public_test_key_bytes = PUBLIC_TEST_KEY_BYTES.map(
        |x| {
          if x == 73 {
            74
          } else {
            x
          }
        }
    );
    let res = check_if_edwardspoint(&public_test_key_bytes);
    assert!(res.is_err())
  }

}

