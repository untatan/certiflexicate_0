

// certiflexicate_secret_key

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



#[cfg(test)]
mod tests {

  use toml as tomler;

  use super::{
    super::{
      Certiflexicate,
      CERTIFICATE_STRING_VALID_001,
      SECRET_TEST_KEY_BYTES,
    },
  };


  #[test]
  fn certificate_self_signed_attach_secret_key_suc_001() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(CERTIFICATE_STRING_VALID_001) {
      assert!(
          cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          ).is_ok()
      );
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_attach_secret_key_suc_002() {
    let secret_test_key_bytes = SECRET_TEST_KEY_BYTES.map(
        |x| {x}
    );
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(CERTIFICATE_STRING_VALID_001) {
      assert!(
          cert
          .attach_secret_key(
              &secret_test_key_bytes,
          ).is_ok()
      );
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_attach_secret_key_fail_001() {
    let secret_test_key_bytes = SECRET_TEST_KEY_BYTES.map(
        |x| {
          if x == 0 {
            1
          } else {
            x
          }
        }
    );
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(CERTIFICATE_STRING_VALID_001) {
      assert!(
          cert
          .attach_secret_key(
              &secret_test_key_bytes,
          ).is_err()
      );
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_attach_secret_key_fail_002() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(CERTIFICATE_STRING_VALID_001) {
      assert!(
          cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          ).is_ok()
      );
      assert!(
          cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          ).is_err()
      );
    } else {
      panic!();
    };
  }

}

