

// format_conversions

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

  use serde_json;
  use serde_pickle;
  use serde_yml;
  use toml as tomler;

  use super::{
    super::{
      Certiflexicate,
      CERTIFICATE_STRING_VALID_001,
      DataContent,
      SECRET_TEST_KEY_BYTES,
    },
  };


  #[test]
  fn certificate_format_toml_json_suc_001() {
    if let Ok(cert1) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      if let Ok(json_string) = serde_json::to_string(&cert1) {
        if let Ok(
            cert2
        ) = serde_json::from_str::<Certiflexicate>(&json_string) {
          assert_eq!(cert1, cert2);
        } else {
          panic!();
        }
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_format_with_data_toml_json_suc_001() {
    if let Ok(mut cert1) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      let attatched = cert1
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      let v = vec![0];
      let r = cert1.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_ok());
      if let Ok(json_string) = serde_json::to_string(&cert1) {
        if let Ok(
            cert2
        ) = serde_json::from_str::<Certiflexicate>(&json_string) {
          if let Ok(toml_string) = tomler::to_string(&cert1) {
            if let Ok(
                cert3
            ) = tomler::from_str::<Certiflexicate>(&toml_string) {
              assert_eq!(cert3, cert2);
            } else {
              panic!();
            }
          } else {
            panic!();
          }
        } else {
          panic!();
        }
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_format_toml_yaml_suc_001() {
    if let Ok(cert1) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      if let Ok(yaml_string) = serde_yml::to_string(&cert1) {
        if let Ok(
            cert2
        ) = serde_yml::from_str::<Certiflexicate>(&yaml_string) {
          assert_eq!(cert1, cert2);
        } else {
          panic!();
        }
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_format_with_data_toml_yaml_suc_001() {
    if let Ok(mut cert1) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      let attatched = cert1
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      let v = vec![0];
      let r = cert1.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_ok());
      if let Ok(yaml_string) = serde_yml::to_string(&cert1) {
        if let Ok(
            cert2
        ) = serde_yml::from_str::<Certiflexicate>(&yaml_string) {
          if let Ok(toml_string) = tomler::to_string(&cert1) {
            if let Ok(
                cert3
            ) = tomler::from_str::<Certiflexicate>(&toml_string) {
              assert_eq!(cert3, cert2);
            } else {
              panic!();
            }
          } else {
            panic!();
          }
        } else {
          panic!();
        }
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_format_toml_pickle_suc_001() {
    if let Ok(cert1) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      if let Ok(
          bytes_vec
      ) = serde_pickle::to_vec(&cert1, Default::default()) {
        if let Ok(
            cert2
        ) = serde_pickle::from_slice::<Certiflexicate>(
            &bytes_vec,
            Default::default(),
        ) {
          assert_eq!(cert1, cert2);
        } else {
          panic!();
        }
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_format_with_data_toml_pickle_suc_001() {
    if let Ok(mut cert1) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      let attatched = cert1
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      let v = vec![0];
      let r = cert1.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_ok());
      if let Ok(
          bytes_vec
      ) = serde_pickle::to_vec(&cert1, Default::default()) {
        if let Ok(
            cert2
        ) = serde_pickle::from_slice::<Certiflexicate>(
            &bytes_vec,
            Default::default(),
        ) {
          if let Ok(toml_string) = tomler::to_string(&cert1) {
            if let Ok(
                cert3
            ) = tomler::from_str::<Certiflexicate>(&toml_string) {
              assert_eq!(cert3, cert2);
            } else {
              panic!();
            }
          } else {
            panic!();
          }
        } else {
          panic!();
        }
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

}

