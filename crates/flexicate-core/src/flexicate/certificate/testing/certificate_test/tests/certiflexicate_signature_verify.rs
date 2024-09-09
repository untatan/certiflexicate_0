

// certiflexicate_signature_verify

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
      DataFields,
    },
  };


  #[test]
  fn certificate_self_signed_signature_verify_suc_001() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
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
  fn certificate_self_signed_signature_verify_suc_002() {
    if let Ok(
        mut cert
    ) = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001,
    ) {
      let sigs = cert
          .get_verified_but_unchecked_signatures(
              &[DataFields::Bytes],
          ).unwrap()
      ;
      assert!(sigs.len() == 0);
    } else {
      panic!();
    };
  }

}

