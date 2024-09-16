

// signatures_values_getters_setters

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
  AcceptState,
  PublicKeyInfo,
  SignatureData,
  VerifyState,
  super::{
    signature_fields::{
      CertiflexicateFieldTypes,
      field_types::{
        sort_claimed_signed_fields,
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

  pub(
      super
  ) fn set_claimed_signed_fields(
      &mut self,
      mut claimed_signed_fields: Vec<CertiflexicateFieldTypes>,
  ) {
    sort_claimed_signed_fields(&mut claimed_signed_fields);
    self.claimed_signed_fields = claimed_signed_fields;
  }

  pub(
      super
  ) fn get_nonce_str(&self) -> &str {
    &self.nonce
  }

  pub(
      in super::super
  ) fn get_nonce_string(&self) -> String {
    self.nonce.clone()
  }

  pub(
      in super::super
  ) fn get_claimed_fields(
      &self,
  ) -> &Vec<CertiflexicateFieldTypes> {
    &self.claimed_signed_fields
  }

  pub(
      in super::super
  ) fn get_accepted_base64(
      &self,
  ) -> &str {
    &self.accepted_base64
  }

  pub(
      in super::super
  ) fn get_accept_state(
      &self,
  ) -> &AcceptState {
    &self.accept_state
  }

  pub(
      in super::super
  ) fn get_self_signed_fields_once_at_load(
      &self,
      pki: &PublicKeyInfo,
  ) -> Option<Vec<CertiflexicateFieldTypes>> {
    if let Some(pk) = &self.public_sig_key_info {
      if pk == pki
          && self.verify_state == VerifyState::Verified
          && self.claimed_self_signature
          && self.self_signed
          && !self.verified_signed_fields.is_empty()
          && !self.claimed_signed_fields.is_empty()
          && self.verified_signed_fields == self.claimed_signed_fields
      {
        Some(self.verified_signed_fields.clone())
      } else {
        None
      }
    } else {
      None
    }
  }

  pub(
      super
  ) fn get_sig_public_key_info_ref(
      &self,
  ) -> Result<
      &PublicKeyInfo,
      ErrorCertiflexicate,
  > {
    if let Some(ref pk) = self.public_sig_key_info {
      Ok(pk)
    } else {
      Err(
          ErrorCertiflexicate::invalid_sig_err(
              "no public key",
          )
      )
    }
  }

  pub(
      super
  ) fn get_sig_public_key_info_clone_clean(
      &self,
  ) -> Result<
      PublicKeyInfo,
      ErrorCertiflexicate,
  > {
    let pk = self.get_sig_public_key_info_ref()?;
    Ok(pk.get_pk_clone_clean())
  }

  pub(
      in super::super
  ) fn signatures_equal_wo_isolation(
      &self,
      sig: &SignatureData,
  ) -> bool {
    self.version == sig.version
        && self.base64 == sig.base64
        && self.nonce == sig.nonce
        && self.identifier == sig.identifier
        && self.comment == sig.comment
        && self.start_date == sig.start_date
        && self.stop_date == sig.stop_date
        && self.signed_fields == sig.signed_fields
        && self.accepted_base64 == sig.accepted_base64
        && self.public_sig_key_info == sig.public_sig_key_info
        && self.datetime_start == sig.datetime_start
        && self.datetime_stop == sig.datetime_stop
        && self.claimed_signed_fields == sig.claimed_signed_fields
        && self.verified_signed_fields == sig.verified_signed_fields
        && self.claimed_self_signature == sig.claimed_self_signature
        && self.self_signed == sig.self_signed
        && self.verify_state == sig.verify_state
        && self.accept_state == sig.accept_state
  }

}


impl SignatureData {

  pub(
      in super::super
  ) fn set_new_verification_state(
      &mut self,
      pki: &PublicKeyInfo,
      new_state_verify: VerifyState,
      self_signed: bool,
      new_state_accept_opt: Option<AcceptState>,
  ) -> Result<
      bool,
      ErrorCertiflexicate,
  > {
    let mut changes = 0;
    if self.verified_signed_fields.is_empty()
        && !self.claimed_signed_fields.is_empty()
        && !self.self_signed
    {
      if self.verify_state != new_state_verify {
        if new_state_verify == VerifyState::Verified {
          self.verified_signed_fields = self.claimed_signed_fields.clone();
        };
        self.verify_state = new_state_verify;
        changes += 1;
      };
      if let Some(new_state_accept) = new_state_accept_opt {
        if new_state_accept != self.accept_state {
          self.accept_state = new_state_accept;
          changes += 1;
        };
      };
      if let Some(pk) = &self.public_sig_key_info {
        if self.claimed_self_signature
            && self_signed
            && pk.equal_wo_keys_data(pki)
        {
          self.self_signed = self_signed;
          changes += 1;
        };
      };
    };
    Ok(changes > 0)
  }

}


impl SignatureData {

  pub(
      in super::super
  ) fn clone_isolated(
      &self,
  ) -> SignatureData {
    let mut sig = self.clone();
    sig.is_isolated_clone = true;
    sig.cert_has_same_public_key = false;
    sig
  }

}

