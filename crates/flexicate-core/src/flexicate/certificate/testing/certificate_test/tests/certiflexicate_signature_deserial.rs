

// certiflexicate_signature_deserial

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
  fn certificate_created_self_signed_signature_edit_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"OlPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err())
  }
  
  #[test]
  fn certificate_created_self_signed_signature_edit_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"oolPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_created_self_signed_signature_edit_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"lPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_created_self_signed_signature_edit_fail_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"0lPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_created_self_signed_signature_edit_fail_005() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "DEI6IfGqkPZbOamIsWEAg==",
            "dDEI6IfGqkPZbOamIsWEAg==",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ=\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ===\"",
            1,
        )
    );
    assert!(res.is_err())
  }
  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ+=\"",
            1,
        )
    );
    assert!(res.is_err())
  }
  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_fail_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \" \"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"\"",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_suc_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "acceptedbase64 = \"!\"",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_created_self_signed_signature_acceptbase64_edit_suc_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_verify_signature_signed_fields_order_fail_001() {
    let s = CERTIFICATE_STRING_VALID_001.replacen(
        "          \"public_signing_key\",\n          \"signature_data\",",
        "          \"signature_data\",\n          \"public_signing_key\",",
        1,
    );
    let res = tomler::from_str::<Certiflexicate>(
        &s
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_verify_signature_signed_fields_fail_001() {
    let s = CERTIFICATE_STRING_VALID_001.replacen(
        "          \"public_signing_key\",",
        "          \"public_signing_key\",\n          \"unknown\",",
        1,
    );
    let res = tomler::from_str::<Certiflexicate>(
        &s
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_verify_signature_signed_fields_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "          \"public_signing_key\",",
            "",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_verify_signature_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z",
            "5odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_verify_signature_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z",
            "5odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z",
            2,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_verify_signature_fail_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==",
            "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg=",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_twice_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n  ",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n      [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1\n      base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"\n      signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]\n\n      [signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_twice_different_nonce_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n  ",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n      [signatures.z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1\n      base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"\n      signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]\n\n      [signatures.z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_signature_twice_different_nonce_suc_002() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n  ",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n      [signatures.z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm]\n      version = 1\n      base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"\n      signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]\n\n      [signatures.z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
            1,
        )
    ) {
      let sigs = cert.get_verified_but_unchecked_signatures(&[]).unwrap();
      assert!(sigs.len() == 1);
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"\"",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_suc_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonc = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_suc_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "Nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_suc_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "NONCE = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"zZ7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"!7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_005() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \" \"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_006() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"\n      nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_007() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce == \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_nonce_diff_fail_008() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce : \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_wo_signature_publickey_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "",
            1,
        )
    );
    assert!(res.is_ok())
  }

  #[test]
  fn certificate_self_signed_signature_wo_signature_publickey_suc_002() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "",
            1,
        )
    ) {
      let sigs = cert.get_verified_but_unchecked_signatures(&[]).unwrap();
      assert!(sigs.len() == 1);
    } else {
      panic!();
    };
  }
  
  #[test]
  fn certificate_self_signed_signature_signature_publickey_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"iIjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_signature_publickey_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"ijD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            1,
        )
    );
    assert!(res.is_err())
  }

  #[test]
  fn certificate_self_signed_signature_signature_publickey_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "[signatures.z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            1,
        )
    );
    assert!(res.is_err())
  }
  
  #[test]
  fn certificate_self_signed_signature_signature_publickey_fail_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-Z\"\n",
            1,
        )
    );
    assert!(res.is_err())
  }

}

