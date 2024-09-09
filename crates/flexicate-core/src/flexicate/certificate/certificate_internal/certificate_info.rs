

// certificate_info

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



use super::{
  Certiflexicate,
  PublicKeyInfo,
  ErrorCertiflexicate,
  super::{
    signature_fields::{
      CertiflexicateFieldTypes,
    },
    signatures::{
      signatures_signable_data::{
        DataFields,
      },
    },
  },
};


impl Certiflexicate {

  pub(
      super
  ) fn known_fields_that_have_data(
      &self,
  ) -> Vec<CertiflexicateFieldTypes> {
    let mut v = Vec::new();
    v.push(CertiflexicateFieldTypes::CertiflexicateIdentifier);
    v.push(CertiflexicateFieldTypes::CertiflexicateVersion);
    if self.public_key_info.is_some() {
      v.push(CertiflexicateFieldTypes::CertiflexicatePublicKey);
    };
    if self.byte_content.is_some() {
      v.push(CertiflexicateFieldTypes::CertiflexicateByteContent);
    };
    if self.signatures.is_some() {
      v.push(CertiflexicateFieldTypes::CertiflexicateSignatureData);
    };
    // TODO extend on new fields
    v
  }

   pub(
      super
  ) fn get_signable_datas(
      &self,
  ) -> Result<
      Vec<DataFields>,
      ErrorCertiflexicate,
  > {
    if self.public_key_info.is_some() {
      let vect = CertiflexicateFieldTypes
          ::filter_additional_fields_if_necessary_fields_are_included(
              &self.known_fields_that_have_data(),
          )
      ?;
      Ok(CertiflexicateFieldTypes::get_additional_signables(&vect))
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "no public key",
      ))
    }
  }

  #[allow(dead_code)]
  pub(
      in super::super
  ) fn get_public_key_field_content(
      &self,
  ) -> &Option<PublicKeyInfo> {
    &self.public_key_info
  }

  pub(
      in super::super
  ) fn get_public_key_info_ref(
      &self,
  ) -> Result<
      &PublicKeyInfo,
      ErrorCertiflexicate,
  > {
    if let Some(ref pk) = self.public_key_info {
      Ok(pk)
    } else {
      Err(
          ErrorCertiflexicate::invalid_pk_err(
              "missing public key in certiflexicate",
          )
      )
    }
  }

  pub(super) fn get_public_key_info_mut_ref(
      &mut self,
  ) -> Result<
      &mut PublicKeyInfo,
      ErrorCertiflexicate,
  > {
    if let Some(ref mut pk) = self.public_key_info {
      Ok(pk)
    } else {
      Err(
          ErrorCertiflexicate::invalid_pk_err(
              "no public key in certiflexicate",
          )
      )
    }
  }

}

