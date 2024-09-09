

// certiflexicate_builder

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
      CertiflexicateBuilder,
      CERTIFICATE_STRING_VALID_001,
      DataContent,
      DataFields,
      PublicKeyInfo,
      PUBLICKEY_STRING_VALID_001,
      SECRET_TEST_KEY_BYTES,
      SignatureData,
      SIGNATURE_STRING_VALID_001,
      SIGNATURE_STRING_DATA_ADDED_VALID_001,
    },
  };


  #[test]
  fn certificate_self_signed_build_version_suc_001() {
    let builder = CertiflexicateBuilder::new_from_version(None);
    assert!(builder.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_version_suc_002() {
    let builder = CertiflexicateBuilder::new_from_version(Some(1));
    assert!(builder.is_ok());
  }

  #[test]
  fn certificate_self_signed_build_version_fail_001() {
    let builder = CertiflexicateBuilder::new_from_version(Some(0));
    assert!(builder.is_err());
  }

  #[test]
  fn certificate_self_signed_build_version_fail_002() {
    let builder = CertiflexicateBuilder::new_from_version(Some(2));
    assert!(builder.is_err());
  }

  #[test]
  fn certificate_self_signed_build_version_fail_003() {
    let builder = CertiflexicateBuilder::new_from_version(Some(3));
    assert!(builder.is_err());
  }

  #[test]
  fn certificate_self_signed_build_version_fail_004() {
    let builder = CertiflexicateBuilder::new_from_version(Some(99));
    assert!(builder.is_err());
  }

  #[test]
  fn certificate_self_signed_build_adddata_suc_001() {
    let builder = CertiflexicateBuilder::new_from_version(None);
    assert!(builder.is_ok());
    let b2 = builder.unwrap().add_data(DataContent::Bytes(vec![0]));
    assert!(b2.is_ok());
    
  }

  #[test]
  fn certificate_self_signed_build_adddata_fail_001() {
    let builder = CertiflexicateBuilder::new_from_version(None);
    assert!(builder.is_ok());
    let b2 = builder.unwrap().add_data(DataContent::Bytes(vec![]));
    assert!(b2.is_err());
  }

  #[test]
  fn certificate_self_signed_build_adddata_fail_002() {
    let builder = CertiflexicateBuilder::new_from_version(None);
    assert!(builder.is_ok());
    if let Ok(mut b1) = builder {
      let b2 = b1.add_data(DataContent::Bytes(vec![0]));
      assert!(b2.is_ok());
      let b3 = b1.add_data(DataContent::Bytes(vec![0]));
      assert!(b3.is_err());
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_add_publickey_suc_001() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_add_publickey_fail_001() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk.clone());
        assert!(r1.is_ok());
        let r2 = b.add_public_key(pk);
        assert!(r2.is_err());
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_add_publickey_fail_002() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        let r2 = b.build();
        assert!(r2.is_err());
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_add_signature_suc_001() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      if let Ok(sig) = tomler::from_str::<SignatureData>(
          &SIGNATURE_STRING_VALID_001
      ) {
        let builder = CertiflexicateBuilder::new_from_version(None);
        assert!(builder.is_ok());
        if let Ok(mut b) = builder {
          let r1 = b.add_public_key(pk);
          assert!(r1.is_ok());
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
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
  fn certificate_self_signed_build_add_signature_fail_001() {
    if let Ok(sig) = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_signature(sig);
        assert!(r1.is_err());
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_add_signature_fail_002() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      if let Ok(sig) = tomler::from_str::<SignatureData>(
          &SIGNATURE_STRING_VALID_001
      ) {
        let builder = CertiflexicateBuilder::new_from_version(None);
        assert!(builder.is_ok());
        if let Ok(mut b) = builder {
          let r1 = b.add_public_key(pk);
          assert!(r1.is_ok());
          let r2 = b.add_signature(sig.clone());
          assert!(r2.is_ok());
          let r3 = b.add_signature(sig);
          assert!(r3.is_err());
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
  fn certificate_self_signed_build_build_suc_001() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          let r3 = b.build();
          assert!(r3.is_ok());
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
  fn certificate_self_signed_build_build_suc_002() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          let r3 = b.add_data(DataContent::Bytes(vec![0]));
          assert!(r3.is_ok());
          if let Ok(sig2) = tomler::from_str::<SignatureData>(
              &SIGNATURE_STRING_DATA_ADDED_VALID_001
          ) {
            let r4 = b.add_signature(sig2);
            assert!(r4.is_ok());
            let r5 = b.build();
            assert!(r5.is_ok());
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
  fn certificate_self_signed_build_build_suc_003() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          let r3 = b.add_data(DataContent::Bytes(vec![0]));
          assert!(r3.is_ok());
          if let Ok(sig2) = tomler::from_str::<SignatureData>(
              &SIGNATURE_STRING_DATA_ADDED_VALID_001
          ) {
            let r4 = b.add_signature(sig2);
            assert!(r4.is_ok());
            let r5 = b.build();
            assert!(r5.is_ok());
            if let Ok(mut cert) = r5 {
              assert!(
                  cert
                      .get_verified_but_unchecked_signatures(&[])
                      .unwrap()
                      .len() 
                  == 2
              );
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
  fn certificate_self_signed_build_build_suc_004() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          let r3 = b.add_data(DataContent::Bytes(vec![0]));
          assert!(r3.is_ok());
          if let Ok(sig2) = tomler::from_str::<SignatureData>(
              &SIGNATURE_STRING_DATA_ADDED_VALID_001
          ) {
            let r4 = b.add_signature(sig2);
            assert!(r4.is_ok());
            let r5 = b.build();
            assert!(r5.is_ok());
            if let Ok(mut cert) = r5 {
              assert!(
                  cert
                      .get_verified_but_unchecked_signatures(&[])
                      .unwrap()
                      .len() 
                  == 2
              );
              let attached = cert
                  .attach_secret_key(
                      &SECRET_TEST_KEY_BYTES,
                  )
              ;
              assert!(attached.is_ok());
              assert!(
                  cert
                      .create_and_add_self_signed_signature(
                          &[DataFields::Bytes],
                      ).is_ok()
              );
              assert!(
                  cert
                      .get_verified_but_unchecked_signatures(&[])
                      .unwrap()
                      .len() 
                  == 3
              );
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
  fn certificate_self_signed_build_build_suc_005() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          let r3 = b.build();
          assert!(r3.is_ok());
          if let Ok(cert1) = r3 {
            if let Ok(cert2) = tomler::from_str::<Certiflexicate>(
                &CERTIFICATE_STRING_VALID_001,
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
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_build_fail_001() {
    let builder = CertiflexicateBuilder::new_from_version(None);
    assert!(builder.is_ok());
    if let Ok(b) = builder {
      let r1 = b.build();
      assert!(r1.is_err());
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_build_fail_002() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        let r2 = b.build();
        assert!(r2.is_err());
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_build_fail_003() {
    if let Ok(sig) = tomler::from_str::<SignatureData>(
        &SIGNATURE_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_signature(sig.clone());
        assert!(r1.is_err());
        let r2 = b.build();
        assert!(r2.is_err());
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn certificate_self_signed_build_build_fail_004() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          let r3 = b.add_data(DataContent::Bytes(vec![0]));
          assert!(r3.is_ok());
          let r4 = b.build();
          assert!(r4.is_err());
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
  fn certificate_self_signed_build_build_fail_005() {
    if let Ok(pk) = tomler::from_str::<PublicKeyInfo>(
        &PUBLICKEY_STRING_VALID_001
    ) {
      let builder = CertiflexicateBuilder::new_from_version(None);
      assert!(builder.is_ok());
      if let Ok(mut b) = builder {
        let r1 = b.add_public_key(pk);
        assert!(r1.is_ok());
        if let Ok(sig) = tomler::from_str::<SignatureData>(
            &SIGNATURE_STRING_VALID_001
        ) {
          let r2 = b.add_signature(sig);
          assert!(r2.is_ok());
          if let Ok(sig2) = tomler::from_str::<SignatureData>(
              &SIGNATURE_STRING_DATA_ADDED_VALID_001
          ) {
            let r4 = b.add_signature(sig2);
            assert!(r4.is_ok());
            let r3 = b.build();
            assert!(r3.is_err());
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

