

// certificate_internal

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



pub(super) mod certiflexicate_builder;
pub(super) mod certificate_data_content;
pub(super) mod certificate_serial;

mod certificate_content;
mod certificate_create;
mod certificate_data_and_signatures;
mod certificate_deserialize;
mod certificate_info;
mod certificate_key_attach;
mod certificate_signature_create;
mod certificate_signature_verify;
mod certificate_validate;


use certificate_data_content::{
  DataContent,
};

use super::{
  Certiflexicate,
  CertiflexicateSerial,
  PublicKeyInfo,
  SignatureData,
  signature_fields::{
    CertiflexicateFieldTypes,
  },
  signatures::{
    signatures_accepted::{
      SignatureAccepted,
    },
    signatures_signable_data::{
      DataFields,
    },
  },
  super::{
    error::{
      ErrorCertiflexicate,
    },
  },
};


const CERTIFLEXICATEIDENTIFIER: &str = "certiflexicate";


impl Certiflexicate {

  pub(
      super
  ) fn create_new_self_signed_internal(
      secret_key_data: Option<&[u8; 32]>,
  ) -> Result<
      (
          Certiflexicate,
          [u8; 32],
      ),
      ErrorCertiflexicate,
  > {
    Certiflexicate::new_current_with_new_keys_self_signed(secret_key_data)
  }

  pub(
      super
  ) fn get_public_key_info_internal(
      &self,
  ) -> Result<
      PublicKeyInfo,
      ErrorCertiflexicate,
  > {
    self.get_public_key_info_clone_clean()
  }

  pub(
      super
  ) fn get_verified_but_unchecked_signatures_internal(
      &mut self,
      limited_to: &[DataFields],
  ) -> Result<
      Vec<SignatureAccepted>,
      ErrorCertiflexicate,
  > {
    self.get_all_verified_but_unchecked_signatures_internal(limited_to)
  }

  pub(
      super
  ) fn get_signable_data_fields_internal(
      &self,
  ) -> Result<
      Vec<DataFields>,
      ErrorCertiflexicate,
  > {
    self.get_signable_datas()
  }

  pub(
      super
  ) fn attach_secret_key_internal(
      &mut self,
      secret_key: &[u8; 32],
  ) -> Result<(), ErrorCertiflexicate> {
    self.attach_unencrypted_ed25519_1_secret_key_to_cert_for_self_signing(
        secret_key,
    )
  }

  pub(
      super
  ) fn create_and_add_self_signed_signature_internal(
      &mut self,
      extended_to_fields: &[DataFields],
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    self.create_and_add_self_signed_signature_to_this_cert(
        extended_to_fields,
    )
  }

  pub(
      super
  ) fn create_and_add_signed_signature_to_other_certiflexicate_internal(
      &self,
      other_certiflexicate: &mut Certiflexicate,
      extended_to_fields: &[DataFields],
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    self.create_and_add_signed_signature_to_other_cert(
        other_certiflexicate,
        extended_to_fields,
    )
  }

  pub(
      super
  ) fn accept_signature_internal(
      &mut self,
      signature: &SignatureData,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.accept_a_signature_in_this_cert(signature)
  }

  pub(
      super
  ) fn add_new_data_and_create_self_signed_signature_internal(
      &mut self,
      data: DataContent,
  ) -> Result<SignatureData, ErrorCertiflexicate> {
    self.add_data_and_create_self_signed_signature(data)
  }

  pub(
      super
  ) fn get_data_with_signatures_internal(
      &mut self,
      field: DataFields,
  ) -> Result<
      (
          DataContent,
          Vec<SignatureAccepted>,
      ),
      ErrorCertiflexicate,
  > {
    self.get_data_for_field_with_signatures(field)
  }

}

