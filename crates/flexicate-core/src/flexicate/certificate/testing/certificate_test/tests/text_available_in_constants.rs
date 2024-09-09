

// text_available_in_constants

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

  use super::{
    super::{
      CERTIFICATE_STRING_VALID_001,
      PUBLICKEY_STRING_VALID_001,
      SIGNATURE_STRING_VALID_001,
    },
  };


  #[test]
  fn certiflexicate_test_has_text_suc_001() {
    assert!(CERTIFICATE_STRING_VALID_001.contains("DEI6IfGqkPZbOamIsWEAg=="));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_002() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_003() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_004() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_005() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "          \"public_signing_key\",",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_006() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "          \"signature_data\",",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_007() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "          \"public_signing_key\",\n          \"signature_data\",",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_008() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "\n\n",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_009() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "of_type = \"ed25519_1\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_010() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_011() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_012() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "[public_signing_key]\n      version = 1",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_013() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_014() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_015() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "certiflexicate = \"certiflexicate\"\n      version = 1",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_016() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n  ",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_017() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_018() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_019() {
    assert!(CERTIFICATE_STRING_VALID_001.contains(
        "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_200() {
    assert!(PUBLICKEY_STRING_VALID_001.contains(
        "version = 1",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_201() {
    assert!(PUBLICKEY_STRING_VALID_001.contains(
        "of_type = \"ed25519_1\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_202() {
    assert!(PUBLICKEY_STRING_VALID_001.contains(
        "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_203() {
    assert!(PUBLICKEY_STRING_VALID_001.contains(
        "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_300() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "version = 1",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_301() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_302() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_303() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_304() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_305() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "[public_signing_key]",
    ));
  }

  #[test]
  fn certiflexicate_test_has_text_suc_306() {
    assert!(SIGNATURE_STRING_VALID_001.contains(
        "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
    ));
  }

}

