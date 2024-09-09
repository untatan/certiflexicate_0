

// signature_data_struct

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
      SignatureData,
      SIGNATURE_STRING_VALID_001,
      SIGNATURE_STRING_DATA_ADDED_VALID_001,
    },
  };


  #[test]
  fn certificate_self_signed_build_signature_suc_001() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_002() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"zZ7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_003() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_suc_004() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_005() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"!7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_006() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "Nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_007() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "nonce = \"\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_008() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "NONCE = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_009() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "nonce = \"Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm\"",
            "",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_010() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "Accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_011() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "ACCEPTED_BASE64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_012() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_013() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"1Cxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_014() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_DATA_ADDED_VALID_001
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_015() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]",
            "[public_signing_ke]",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_016() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]",
            "[public_signing_keys]",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_suc_017() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_001() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]",
            "[[public_signing_key]]",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_002() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]",
            "[public_signing_key",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_003() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]",
            "[public_signing_key]\nversion = 2",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_004() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]",
            "",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_005() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "version = 0",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_006() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "version = 2",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_007() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "version = 99",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_008() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "version = \"1\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_009() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "Version = 1",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_010() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_011() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "versioN = 1",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_012() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "version = 1",
            "version = 1+1",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_013() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"lPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_014() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"oolPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_015() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \" lPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_016() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"+lPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_017() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_018() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \" \"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_019() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_020() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "Base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_021() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "BASE64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_022() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 : \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_023() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"\nbase64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_024() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            "base64 = \"olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"\nbase64 = \"OlPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_025() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"pPCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_026() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"Cxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_027() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \"!Cxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_028() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "accepted_base64 = \" \"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_029() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            "signed_fields = [\n          \"lexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_030() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          ]",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_031() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            "signed_field = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_032() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            "",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_033() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            "signed_fields = [\n          \"flexicate\",\n          \"signature_data\",\n          \"signature_data\",\n      ]",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_signature_fail_034() {
    let res = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "signed_fields = [\n          \"flexicate\",\n          \"public_signing_key\",\n          \"signature_data\",\n      ]",
            "signed_fields = [\n          \"flexicate\",\n          \"signature_data\",\n          \"public_signing_key\",\n      ]",
            1,
        )
    );
    assert!(res.is_err());
  }

}

