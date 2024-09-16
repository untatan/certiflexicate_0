

// api

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



mod api_01 {

  use super::{
    super::{
      Certiflexicate,
      DataFields,
      PublicKeyInfo,
      SignatureAccepted,
      SignatureData,
      certificate_internal::{
        certificate_data_content::{
          DataContent,
        },
      },
      super::{
        error::{
          ErrorCertiflexicate,
        },
      },
    },
  };


  impl Certiflexicate {

    /// Creates a *`Certiflexicate`* with default values
    /// including a self signed public key.
    /// Shareable if serialized.
    ///
    ///
    /// Instead of generating a new key pair, provided `secret_key_data`
    /// is used to add the public key. **`secret_key_data` has to be
    /// derived from a valid ed25519-dalek signing key!**
    ///
    ///
    /// The returned `[u8; 32]` is the unencrypted secret key which is needed
    /// to create or add more signatures.
    ///
    /// **It should be stored encrypted and securely!**
    ///
    pub fn create_new_self_signed(
        secret_key_data: Option<&[u8; 32]>,
    ) -> Result<
        (
            Certiflexicate,
            [u8; 32],
        ),
        ErrorCertiflexicate,
    > {
      Certiflexicate::create_new_self_signed_internal(secret_key_data)
    }

    /// Get the PublicKeyInfo
    pub fn get_public_key_info(
        &self,
    ) -> Result<
        PublicKeyInfo,
        ErrorCertiflexicate,
    > {
      self.get_public_key_info_internal()
    }

    /// Get available verified `SignatureData`
    /// wrapped into `SignatureAccepted`.
    ///
    /// Constraints are **not** checked.
    ///
    /// With an empty `limited_to_fields`, all signatures which meet
    /// at least the minimum requirements are collected.
    ///
    /// With `DataFields` in `limited_to_fields`, only `SignatureData`
    /// is returned, that meets the minimum requirements and has verified
    /// signatures for all `DataFields` items each.
    pub fn get_verified_but_unchecked_signatures(
        &mut self,
        limited_to_fields: &[DataFields],
    ) -> Result<
        Vec<SignatureAccepted>,
        ErrorCertiflexicate,
    > {
      self.get_verified_but_unchecked_signatures_internal(limited_to_fields)
    }

    /// Get possible `DataFields` that might be used to create a signature
    /// or get data out of this certiflexicate.
    pub fn get_signable_data_fields(&self) -> Result<
        Vec<DataFields>,
        ErrorCertiflexicate,
    > {
      self.get_signable_data_fields_internal()
    }

    /// Load unencrypted secret key corresponding to the public key
    /// of the certiflexicate; needed for signing after deserialization.
    pub fn attach_secret_key(
        &mut self,
        secret_key: &[u8; 32],
    ) -> Result<(), ErrorCertiflexicate> {
      self.attach_secret_key_internal(
          secret_key,
      )
    }

    /// Adds a new self signed signature to this certiflexicate.
    ///
    /// An empty `extended_to_fields` only signs the required data,
    /// while values in `extended_to_fields` extends the signature to
    /// available data of the named data fields.
    pub fn create_and_add_self_signed_signature(
      &mut self,
      extended_to_fields: &[DataFields],
    ) -> Result<
        SignatureData,
        ErrorCertiflexicate,
    > {
      self.create_and_add_self_signed_signature_internal(extended_to_fields)
    }

    /// Adds a new signed signature to the other certiflexicate with
    /// signature created by keys from this `&self` one.
    ///
    /// `extended_to_fields` is handled as described in 
    /// `create_and_add_self_signed_signature` but is applied to and has to
    /// be available in the other certiflexicate.
    pub fn create_and_add_signed_signature_to_other_certiflexicate(
        &self,
        other_certiflexicate: &mut Certiflexicate,
        extended_to_fields: &[DataFields],
    ) -> Result<
        SignatureData,
        ErrorCertiflexicate,
    > {
      self.create_and_add_signed_signature_to_other_certiflexicate_internal(
          other_certiflexicate,
          extended_to_fields,
      )
    }

    /// Accept `signature` by signing it in this certiflexicate.
    /// As usual, this requires the secret key to be attached.
    pub fn accept_signature(
        &mut self,
        signature: &SignatureData,
    ) -> Result<
        (),
        ErrorCertiflexicate,
    > {
      self.accept_signature_internal(signature)
    }

    /// Tries to add data and sign it.
    pub fn add_new_data_and_create_self_signed_signature(
        &mut self,
        data: DataContent,
    ) -> Result<
        SignatureData,
        ErrorCertiflexicate,
    > {
      self.add_new_data_and_create_self_signed_signature_internal(
          data,
      )
    }

    /// Tries to get signed data with its verified but unchecked signatures.
    pub fn get_data_with_signatures(
        &mut self,
        field: DataFields,
    ) -> Result<
        (
            DataContent,
            Vec<SignatureAccepted>,
        ),
        ErrorCertiflexicate,
    > {
      self.get_data_with_signatures_internal(field)
    }

  }

}

