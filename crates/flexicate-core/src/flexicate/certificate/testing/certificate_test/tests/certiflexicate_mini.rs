

// certiflexicate_mini

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
    },
  };


  #[test]
  fn certiflexicate_mini_suc_001() {
    let c = Certiflexicate::get_defaults();
    let s_opt = tomler::to_string_pretty(&c);
    if let Ok(s) = s_opt {
      assert!("certiflexicate = \"\"\nversion = 0\n" == s);
    } else {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_suc_002() {
    let c = Certiflexicate::new_current();
    assert!(c.seems_valid_cert_minimum().is_ok());
  }

  #[test]
  fn certiflexicate_mini_suc_003() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 1
    "#);
    if res.is_err() {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_identifier_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = ""
        version = 1
    "#);
    if res.is_ok() {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_identifier_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate "
        version = 1
    "#);
    if res.is_ok() {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_identifier_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "Certiflexicate"
        version = 1
    "#);
    if res.is_ok() {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_version_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 2
    "#);
    if res.is_ok() {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_version_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 0
    "#);
    if res.is_ok() {
      panic!();
    };
  }

  #[test]
  fn certiflexicate_mini_version_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 01
    "#);
    if res.is_ok() {
      panic!();
    };
  }

  #[test]
  fn certificate_public_key_only_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 1
        [public_signing_key]
        version = 1
        of_type = "ed25519_1"
        base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
        identifier = "public verify test key"
    "#);
    assert!(res.is_err())
  }

  #[test]
  fn certificate_signature_only_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 1
        [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]
        version = 1
        base64 = "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg=="
        signed_fields = [
            "flexicate",
            "public_signing_key",
            "signature_data",
        ]
        
        [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]
        version = 1
        of_type = "ed25519_1"
        base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
        identifier = "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z"
    "#);
    assert!(res.is_err())
  }

}

