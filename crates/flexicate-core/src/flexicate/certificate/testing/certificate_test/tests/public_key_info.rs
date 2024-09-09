

// public_key_info

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
      PublicKeyInfo,
      PUBLICKEY_STRING_VALID_001,
    },
  };


  #[test]
  fn certificate_self_signed_build_publickey_suc_001() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_publickey_suc_002() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_publickey_suc_003() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"!\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_publickey_suc_004() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \" \"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_publickey_suc_005() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_publickey_suc_006() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"!6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_001() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "of_type = \"ed25519_1\"",
            "",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_002() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "of_type = \"ed25519_1\"",
            "of_type = \"ed25519_0\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_003() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "of_type = \"ed25519_1\"",
            "of_types = \"ed25519_1\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_004() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"iIjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_005() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"jD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_006() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"*jD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_007() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \"\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_008() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "base64 = \" \"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_009() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "Base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_010() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            "BASE64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_011() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "version = 0",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_012() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "version = 2",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_013() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "version = 3",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_014() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "version = 11",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_015() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "version = ",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_016() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "versio = 1",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_017() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "Version = 1",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_018() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "version = \"1\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_019() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "version = 1",
            "VERSION = 1",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_020() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identi fier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_021() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "identifier = \"\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_022() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_023() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "Identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_build_publickey_fail_024() {
    let res = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            "IDENTIFIER = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"",
            1,
        )
    );
    assert!(res.is_err());
  }

}

