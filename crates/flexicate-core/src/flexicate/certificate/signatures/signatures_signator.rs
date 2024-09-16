

// signatures_signator

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



use crate::{
  flexicate::{
    helpers::{
      base64::{
        get_base64_decoded,
        get_urlsafe_string,
      },
      random::{
        get_random_bytes_as_string,
      },
    },
  },
};

use super::{
  AcceptState,
  Certiflexicate,
  PublicKeyInfo,
  SignatureData,
  VerifyState,
  super::{
    signature_fields::{
      CertiflexicateFieldTypes,
      field_types::{
        get_signed_fields_strings_for_fields,
      },
    },
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
  },
};


impl SignatureData {

  fn create_signature(
      &mut self,
      pk: &PublicKeyInfo,
      cert: &Certiflexicate,
      fields: Vec<CertiflexicateFieldTypes>,
      self_signed: bool,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.set_claimed_signed_fields(
        fields
    );
    self.signed_fields = get_signed_fields_strings_for_fields(
        &self.claimed_signed_fields,
    );
    let data = self.get_data_for_signed_fields(cert)?;
    let base64_sig = if !self_signed {
      let signature_base64 = pk.sign_data_with_secret_key_to_base64(
          &data,
      )?;
      self.accept_state = AcceptState::MissingAccept;
      signature_base64
    } else {
      let signature_bytes = pk.sign_data_with_secret_key_to_bytes(&data)?;
      let acceptsignature = pk.sign_data_with_secret_key_to_base64(
          &signature_bytes,
      )?;
      self.accepted_base64 = acceptsignature;
      self.accept_state = AcceptState::SelfAccepted;
      get_urlsafe_string(&signature_bytes)
    };
    self.base64 = base64_sig;
    self.self_signed = self_signed;
    self.verify_state = VerifyState::SignatureCreated;
    self.verified_signed_fields = self.claimed_signed_fields.clone();
    Ok(())
  }

}


impl SignatureData {

  pub(
      in super::super
  ) fn create_first_self_signed_public_key(
      cert: &Certiflexicate,
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    if cert.signatures.is_none() {
      if let Some(public_key_info) = &cert.public_key_info {
        let mut sig = SignatureData::new_current_default_from_public_key(
            public_key_info.get_pk_clone_clean(),
        );
        sig.create_signature(
            public_key_info,
            cert,
            CertiflexicateFieldTypes::get_fields_for_self_signed_public_key(),
            true,
        )?;
        Ok(sig)
      } else {
        Err(ErrorCertiflexicate::signable_err(
            "public key not found in certiflexicate",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "already signed",
      ))
    }
  }

  pub(
      in super::super
  ) fn create_signed_signature(
      pk: &PublicKeyInfo,
      cert: &Certiflexicate,
      fields: Vec<CertiflexicateFieldTypes>,
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    if let Some(signatures) = &cert.signatures {
      let mut nonce_opt = None;
      let mut ct = 0;
      while nonce_opt.is_none() && ct <= 10 {
        ct += 1;
        let nonce = get_random_bytes_as_string(36);
        if !signatures.contains_key(&nonce) {
          nonce_opt = Some(nonce);
        };
      };
      if let Some(nonce) = nonce_opt {
        if let Some(ref public_key_info) = cert.public_key_info {
          let self_sig = public_key_info.equal_wo_keys_data(pk);
          let mut sig = SignatureData
              ::new_current_default_general_with_public_key(
                  pk.get_pk_clone_clean(),
                  nonce,
                  self_sig,
              )
          ;
          sig.create_signature(
              pk,
              cert,
              fields,
              self_sig,
          )?;
          Ok(sig)
        } else {
          Err(ErrorCertiflexicate::signable_err(
              "no public key found in certiflexicate",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::signable_err(
            "no new random nonce found",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "no signatures found in certiflexicate",
      ))
    }
  }

  pub(
      in super::super
  ) fn accept_the_signature_with_key(
      &mut self,
      pk: &PublicKeyInfo,
  ) -> Result<
      String,
      ErrorCertiflexicate,
  > {
    if self.get_accept_state().state_is_not_accepted() {
      let sig = get_base64_decoded(
          &self.base64,
      )?;
      let acceptsignature = pk.sign_data_with_secret_key_to_base64(
          &sig,
      )?;
      self.accepted_base64 = acceptsignature.clone();
      let pk = self.get_sig_public_key_info_ref()?;
      if pk.equal_wo_keys_data(pk) {
        self.accept_state = AcceptState::SelfAccepted;
      } else {
        self.accept_state = AcceptState::ForeignSignatureAccepted;
      };
      Ok(acceptsignature)
    } else {
      Err(ErrorCertiflexicate::accepting_sig(
          "this signature was accepted previously",
      ))
    }
  }

}

