

// certiflexicate_signature_create

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
      SECRET_TEST_KEY_BYTES,
    },
  };


  #[test]
  fn certificate_self_signed_add_self_signature_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      assert!(
          cert
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
      let attached = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attached.is_ok());
      assert!(cert.create_and_add_self_signed_signature(&[]).is_ok());
      assert!(
          cert
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 2
      );
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_add_self_signature_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      assert!(
          cert
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
      assert!(cert.create_and_add_self_signed_signature(&[]).is_err());
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_add_other_signature_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      let mut other = cert.clone();
      let attached = cert
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attached.is_ok());
      assert!(
          other
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
      assert!(cert.create_and_add_signed_signature_to_other_certiflexicate(
          &mut other,
          &[],
      ).is_ok());
      assert!(
          other
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 2
      );
      assert!(
          cert
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
    } else {
      panic!();
    };
  }

  #[test]
  fn certificate_self_signed_add_other_signature_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(cert) = res {
      let mut other = cert.clone();
      assert!(
          other
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
      assert!(cert.create_and_add_signed_signature_to_other_certiflexicate(
          &mut other,
          &[],
      ).is_err());
    } else {
      panic!();
    };
    
  }

  #[test]
  fn certificate_self_signed_add_other_signature_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(cert) = res {
      let mut other = cert.clone();
      assert!(
          other
              .get_verified_but_unchecked_signatures(&[])
              .unwrap()
              .len() == 1
      );
      let attached = other
          .attach_secret_key(
              &SECRET_TEST_KEY_BYTES,
          )
      ;
      assert!(attached.is_ok());
      assert!(cert.create_and_add_signed_signature_to_other_certiflexicate(
          &mut other,
          &[],
      ).is_err());
    } else {
      panic!();
    };
  }

}

