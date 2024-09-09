

// certificate_test

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

  mod format_conversions;
  mod certiflexicate_builder;
  mod certiflexicate_data_content;
  mod certiflexicate_mini;
  mod certiflexicate_public_key_deserial;
  mod certiflexicate_secret_key;
  mod certiflexicate_signature_deserial;
  mod certiflexicate_signature_accept;
  mod certiflexicate_signature_create;
  mod certiflexicate_signature_verify;
  mod public_key_info;
  mod signature_data_struct;
  mod text_available_in_constants;

  use toml as tomler;

  use super::{
    super::{
      super::{
        Certiflexicate,
        CertiflexicateBuilder,
        DataContent,
        DataFields,
        PublicKeyInfo,
        SignatureAccepted,
        SignatureData,
      },
    },
  };


  const SECRET_TEST_KEY_BYTES: [u8; 32] = [
      172, 123, 33, 195, 0, 92, 190, 222, 84, 230, 54,
      163, 8, 250, 226, 106,235, 119, 177, 178, 66, 233,
      17, 201, 216, 168, 29, 182, 142, 43, 228, 78,
  ];

  const CERTIFICATE_STRING_VALID_001: &str = r#"
      certiflexicate = "certiflexicate"
      version = 1

      [public_signing_key]
      version = 1
      of_type = "ed25519_1"
      base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
      identifier = "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z"

      [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]
      version = 1
      base64 = "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg=="
      nonce = "Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm"
      signed_fields = [
          "flexicate",
          "public_signing_key",
          "signature_data",
      ]
      accepted_base64 = "PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ=="

      [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]
      version = 1
      of_type = "ed25519_1"
      base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
      identifier = "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z"
  "#;

  const PUBLICKEY_STRING_VALID_001: &str = r#"
      version = 1
      of_type = "ed25519_1"
      base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
      identifier = "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z"
  "#;

  const SIGNATURE_STRING_VALID_001: &str = r#"
      version = 1
      base64 = "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg=="
      nonce = "Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm"
      signed_fields = [
          "flexicate",
          "public_signing_key",
          "signature_data",
      ]
      accepted_base64 = "PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ=="
      
      [public_signing_key]
      version = 1
      of_type = "ed25519_1"
      base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
      identifier = "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z"
  "#;

  const SIGNATURE_STRING_DATA_ADDED_VALID_001: &str = r#"
      version = 1
      base64 = "vlXptEGljjxD6uicEjItCkcG6T5NuVn4zWMdqwPlsungpIseKDeYYpnlWLBOG0jzhrmZ9iuFNpHLkgoooc6aAw=="
      nonce = "dClq5lIUZxmxvlOWlOPvY4bTiej_vbiVwTThGCVWw2wjV6AX"
      signed_fields = [
          "flexicate",
          "public_signing_key",
          "byte_content",
          "signature_data",
      ]
      accepted_base64 = "IqqlBqmm1R8Xv-m04s6s7Y11Wmt3TzvtzMFkuTo1shsg_FGr76bpc-FcZw3kpqc7evbXiP6f04-xJDnKTYvlBQ=="
      
      [public_signing_key]
      version = 1
      of_type = "ed25519_1"
      base64 = "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
      identifier = "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z"
  "#;


  #[test]
  fn certificate_created_self_signed_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(CERTIFICATE_STRING_VALID_001);
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_created_self_signed_wo_blank_lines_suc_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "\n\n",
            "\n",
            3,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn new_current_with_new_keys_self_signed_001() {
    let c_opt = Certiflexicate::new_current_with_new_keys_self_signed(
        Some(&SECRET_TEST_KEY_BYTES),
    );
    if let Ok((c, sk)) = c_opt {
      let s_opt = tomler::to_string_pretty(&c);
      if let Ok(s) = s_opt {
        assert!(650 == s.len());
        assert_eq!(sk, SECRET_TEST_KEY_BYTES);
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

}

