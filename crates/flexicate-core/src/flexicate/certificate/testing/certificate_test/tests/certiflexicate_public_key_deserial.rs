

// certiflexicate_public_key_deserial

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
    },
  };


  #[test]
  fn certificate_public_key_suc_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    );
    assert!(res.unwrap().public_key_info.unwrap().is_not_useable() == false)
  }

  #[test]
  fn certificate_public_key_suc_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n      not_useable = true\n      \n",
            1,
        )
    );
    assert!(res.unwrap().public_key_info.unwrap().is_not_useable() == false)
  }

  #[test]
  fn certificate_public_key_suc_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n      unknown_value = true\n      \n",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_public_key_wrong_header_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "public_signing_key",
            "public_signing_keys",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_included_unuseable_defaults_001() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 1
        
        [public_signing_key]
        version = 0
        of_type = ""
        base64 = ""
        identifier = ""
        [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]
        version = 1
        base64 = "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg=="
        signed_fields = [
            "flexicate",
            "public_signing_key",
            "signature_data",
        ]
        
        [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]
        version = 0
        of_type = ""
        base64 = ""
        identifier = ""
    "#);
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_included_unuseable_defaults_002() {
    let res = tomler::from_str::<Certiflexicate>(r#"
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
        signed_fields = [
            "flexicate",
            "public_signing_key",
            "signature_data",
        ]
        
        [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]
        version = 0
        of_type = ""
        base64 = ""
        identifier = ""
    "#);
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_included_unuseable_defaults_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "[public_signing_key]\n      version = 0\n      of_type = \"\"\n      base64 = \"\"\n      identifier = \"\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_included_unuseable_defaults_correct_version_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "[public_signing_key]\n      version = 1\n      of_type = \"\"\n      base64 = \"\"\n      identifier = \"\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_of_type_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "of_type = \"ed25519_1\"",
            "of_type = \"ed25519_0\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_of_type_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "of_type = \"ed25519_1\"",
            "of_type = \"ed25519_0\"",
            2,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_version_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[public_signing_key]\n      version = 1",
            "[public_signing_key]\n      version = 0",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_base64_43_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_base64_45_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw0=\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_base64_invalid_char_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnx/=\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_identifier_empty_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_changed_identifier_changed_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"abc\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_doubled_version_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1",
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1\n      version = 1",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_doubled_header_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1",
            "[public_signing_key]\n\n[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_public_key_doubled_header_and_values_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            1,
        )
    );
    assert!(res.is_err())
  }

}

