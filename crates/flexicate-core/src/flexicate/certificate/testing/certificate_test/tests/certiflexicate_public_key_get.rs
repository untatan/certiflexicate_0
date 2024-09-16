

// certiflexicate_public_key_get

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
      PublicKeyInfo,
      SignatureData,
      CERTIFICATE_STRING_VALID_001,
      PUBLICKEY_STRING_VALID_001,
      SECRET_TEST_KEY_BYTES,
      SIGNATURE_STRING_VALID_001,
      SIGNATURE_STRING_DATA_ADDED_VALID_001,
    },
  };


  #[test]
  fn certiflexicate_mini_wo_pk_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(r#"
        certiflexicate = "certiflexicate"
        version = 1
    "#);
    if let Ok(cert) = res {
      assert!(cert.get_public_key_info().is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_get_public_key_suc_001() {
    if let Ok(cert) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      assert!(cert.get_public_key_info().is_ok());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_get_public_key_suc_002() {
    if let Ok(mut cert) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      assert!(
          cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          ).is_ok()
      );
      if let Ok(pk) = cert.get_public_key_info() {
        assert!(!pk.has_secret_key_data());
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_get_public_key_suc_003() {
    if let Ok(mut cert) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      assert!(
          cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          ).is_ok()
      );
      if let Ok(pk) = cert.get_public_key_info() {
        assert!(!pk.has_secret_key_data());
        if let Ok(pki) = tomler::from_str::<PublicKeyInfo>(
            &PUBLICKEY_STRING_VALID_001
        ) {
          assert!(pk == pki);
        } else {
          panic!();
        };
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_fail_001() {
    if let Ok(sig) = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001.replacen(
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "",
            1,
        )
    ) {
      assert!(sig.get_signature_public_key_info().is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_fail_002() {
    if let Ok(sig) = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_DATA_ADDED_VALID_001.replacen(
            "[public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "",
            1,
        )
    ) {
      assert!(sig.get_signature_public_key_info().is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_suc_001() {
    if let Ok(sig) = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001
    ) {
      if let Ok(pk) = sig.get_signature_public_key_info() {
        assert!(!pk.has_secret_key_data());
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_suc_002() {
    if let Ok(sig) = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_DATA_ADDED_VALID_001
    ) {
      if let Ok(pk) = sig.get_signature_public_key_info() {
        assert!(!pk.has_secret_key_data());
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_suc_003() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      if let Ok(
          sigs
      ) = cert.get_verified_but_unchecked_signatures(&[]) {
        assert!(sigs.len() == 1);
        if let Ok(pk) = sigs[0].get_signature_public_key_info() {
          assert!(!pk.has_secret_key_data());
        } else {
          panic!();
        };
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_suc_004() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "[signatures.Z7UV_GrDViT55Blw77NJwHkuvWB5qoKlFl1rmJSoedN3iYLm.public_signing_key]\n      version = 1\n      of_type = \"ed25519_1\"\n      base64 = \"IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw=\"\n      identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n",
            "",
            1,
        )
    ) {
      if let Ok(
          sigs
      ) = cert.get_verified_but_unchecked_signatures(&[]) {
        assert!(sigs.len() == 1);
        if let Ok(pk) = sigs[0].get_signature_public_key_info() {
          assert!(!pk.has_secret_key_data());
        } else {
          panic!();
        };
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_suc_005() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      if let Ok(pki) = cert.get_public_key_info() {
        assert!(!pki.has_secret_key_data());
        if let Ok(
            sigs
        ) = cert.get_verified_but_unchecked_signatures(&[]) {
          assert!(sigs.len() == 1);
          if let Ok(pk) = sigs[0].get_signature_public_key_info() {
            assert!(!pk.has_secret_key_data());
            assert!(pk == pki);
          } else {
            panic!();
          };
        } else {
          panic!();
        };
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_signature_get_public_key_suc_006() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      if let Ok(pki) = cert.get_public_key_info() {
        assert!(!pki.has_secret_key_data());
        if let Ok(
            sigs
        ) = cert.get_verified_but_unchecked_signatures(&[]) {
          assert!(sigs.len() == 1);
          if let Ok(pk) = sigs[0].get_signature_public_key_info() {
            assert!(!pk.has_secret_key_data());
            assert!(pk == pki);
            if let Ok(sig2) = tomler::from_str::<SignatureData>(
                &SIGNATURE_STRING_VALID_001
            ) {
              if let Ok(pki2) = sig2.get_signature_public_key_info() {
                assert!(!pki2.has_secret_key_data());
                assert!(pki == pki2);
                assert!(pk == pki2);
              } else {
                panic!();
              };
            } else {
              panic!();
            };
          } else {
            panic!();
          };
        } else {
          panic!();
        };
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

}

