

// certiflexicate_data_content

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
      DataContent,
      DataFields,
      SECRET_TEST_KEY_BYTES,
    },
  };


  #[test]
  fn certificate_self_signed_signature_content_binary_no_key_fail_001() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      let sigs = cert
          .get_verified_but_unchecked_signatures(&[])
          .unwrap()
      ;
      assert!(sigs.len() == 1);
      let v = vec![0];
      let r = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      //∵ no secret key
      assert!(r.is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_content_binary_empty_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "certiflexicate = \"certiflexicate\"\n      version = 1\n",
            "certiflexicate = \"certiflexicate\"\n      byte_content = []\n      version = 1\n",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_content_wrong_position_ignores_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n\n",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n      byte_content = [1]\n      \n",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_content_wrong_position_ignores_suc_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n  ",
            "identifier = \"6odFgzaD2Pc9uw9GGGzlotdVvXhHLfwndqql97PT7LOECN-z\"\n      byte_content = [1]\n      \n",
            1,
        )
    );
    assert!(res.is_ok());
  }

  #[test]
  fn certificate_self_signed_content_binary_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "certiflexicate = \"certiflexicate\"\n      version = 1\n",
            "certiflexicate = \"certiflexicate\"\n      version = 1\n      byte_content = [0]\n",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_content_binary_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "certiflexicate = \"certiflexicate\"\n      version = 1\n",
            "certiflexicate = \"certiflexicate\"\n      version = 1\n      byte_content = [\"a\"]\n",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_content_binary_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "certiflexicate = \"certiflexicate\"\n      version = 1\n",
            "certiflexicate = \"certiflexicate\"\n      byte_content = [1]\n      version = 1\n",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_content_binary_fail_004() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "          \"public_signing_key\",\n          \"signature_data\",",
            "          \"public_signing_key\",\n          \"byte_content\",\n          \"signature_data\",",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_content_binary_fail_005() {
    let s = &CERTIFICATE_STRING_VALID_001.replacen(
        "certiflexicate = \"certiflexicate\"\n      version = 1\n",
        "certiflexicate = \"certiflexicate\"\n      version = 1\n      byte_content = [0]\n",
        1,
    );
    let res = tomler::from_str::<Certiflexicate>(
        &s.replacen(
            "          \"public_signing_key\",\n          \"signature_data\",",
            "          \"public_signing_key\",\n          \"byte_content\",\n          \"signature_data\",",
            1,
        )
    );
    assert!(res.is_err());
  }

  #[test]
  fn certificate_self_signed_content_binary_adding_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      let attatched = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      let v = vec![0];
      let r = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_ok());
    } else {
      panic!();
    };
    
  }

  #[test]
  fn certificate_self_signed_content_binary_adding_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      let v = vec![1];
      let r = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_content_binary_adding_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      let attatched = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      let v = vec![];
      let r = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_content_binary_adding_fail_003() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      let attatched = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      let v = vec![0];
      let r1 = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v.clone()),
      );
      assert!(r1.is_ok());
      let r2 = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r2.is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_content_binary_signables_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      assert!(cert.get_signable_data_fields().unwrap().len() == 0);
      let attatched = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attatched.is_ok());
      assert!(cert.get_signable_data_fields().unwrap().len() == 0);
      let v = vec![0];
      let r = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v),
      );
      assert!(r.is_ok());
      assert!(cert.get_signable_data_fields().unwrap().len() == 1);
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_content_binary_add_and_get_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      assert!(cert.get_data_with_signatures(DataFields::Bytes).is_err());
      assert!(
          cert
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
      assert!(cert
          .get_verified_but_unchecked_signatures(
              &[DataFields::Bytes],
          ).unwrap()
          .len() == 0
      );
      let attached = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attached.is_ok());
      assert!(cert.get_signable_data_fields().unwrap().len() == 0);
      let v = vec![0];
      let r = cert.add_new_data_and_create_self_signed_signature(
          DataContent::Bytes(v.clone()),
      );
      assert!(r.is_ok());
      assert!(
          cert
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 2
      );
      assert!(cert
          .get_verified_but_unchecked_signatures(
              &[DataFields::Bytes],
          ).unwrap()
          .len() == 1
      );
      let get_res = cert.get_data_with_signatures(DataFields::Bytes);
      assert!(get_res.is_ok());
      if let Ok(d) = get_res {
        assert!(d.1.len() == 1);
        let DataContent::Bytes(data) = d.0;
        assert!(data == v);
      } else {
        panic!();
      };
    } else {
      panic!();
    };
  }

}

