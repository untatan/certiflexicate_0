

// signatures_verificator

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
    },
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
  },
};


impl SignatureData {

  fn verify_signature(
      &self,
      cert: &Certiflexicate,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.verify_state == VerifyState::NoInfo
        && self.verified_signed_fields.is_empty()
        && !self.claimed_signed_fields.is_empty()
    {
      let sig = get_base64_decoded(
          &self.base64,
      )?;
      let pk = self.get_sig_public_key_info_ref()?;
      pk.verify_data_signed_with_public_key(
          &self.get_data_for_signed_fields(cert)?,
          &sig,
      )
    } else {
      Err(ErrorCertiflexicate::verify_sig_err(
          "already verified",
      ))
    }
  }

  fn verify_accept_signature(
      &self,
      cert: &Certiflexicate,
  ) -> Option<AcceptState> {
    if self.accept_state == AcceptState::NoInfo {
      if self.accepted_base64.is_empty() {
        Some(AcceptState::MissingAccept)
      } else if let Ok(sig) = get_base64_decoded(
          &self.base64,
      ) {
        if let Some(ref pki) = cert.public_key_info {
          if let Ok(acceptsig) = get_base64_decoded(
              &self.accepted_base64,
          ) {
            if pki.verify_data_signed_with_public_key(
                &sig,
                &acceptsig,
            ).is_ok() {
              if let Some(pk) = &self.public_sig_key_info {
                if pk.equal_wo_keys_data(pki) {
                  Some(AcceptState::SelfAccepted)
                } else {
                  Some(AcceptState::ForeignSignatureAccepted)
                }
              } else {
                Some(AcceptState::CheckNotPossible)
              }
            } else {
              Some(AcceptState::NotAccepted)
            }
          } else {
            Some(AcceptState::BadData)
          }
        } else {
          Some(AcceptState::CheckNotPossible)
        }
      } else {
        Some(AcceptState::BadData)
      }
    } else {
      None
    }
  }

}


impl SignatureData {

  pub(
      in super::super
  ) fn verify_not_previously_examined_signature(
      &self,
      cert: &Certiflexicate,
      pki: &PublicKeyInfo,
  ) -> Result<
      Option<(VerifyState, bool, Option<AcceptState>)>,
      ErrorCertiflexicate,
  > {
    let state = if self.verify_state == VerifyState::NoInfo
        && !self.self_signed
        && self.verified_signed_fields.is_empty()
        && !self.claimed_signed_fields.is_empty()
    {
      let self_sig = if let Some(pk) = &self.public_sig_key_info {
        pk.equal_wo_keys_data(pki) && self.claimed_self_signature
      } else {
        false
      };
      let mut do_accept_verify = false;
      let verify_state = if self.verify_signature(cert).is_ok() {
        do_accept_verify = true;
        VerifyState::Verified
      } else {
        VerifyState::VerifyFailure
      };
      let accept_verified = if do_accept_verify {
        self.verify_accept_signature(cert)
      } else {
        Some(AcceptState::CheckNotPossible)
      };
      Some((verify_state, self_sig, accept_verified))
    } else {
      None
    };
    Ok(state)
  }

  pub(
     in super::super
  ) fn is_verified_state_one_of(
      &self,
      verify_states: &[VerifyState],
  ) -> bool {
    verify_states.contains(&self.verify_state)
  }

  pub(
     in super::super
  ) fn is_verified_for_all_of(
      &self,
      fields: &[CertiflexicateFieldTypes],
  ) -> bool {
    let mut found_fields: Vec<
        &CertiflexicateFieldTypes
    > = Vec::with_capacity(fields.len());
    for item in fields {
      if self.verified_signed_fields.contains(item)
          && !found_fields.contains(&item)
      {
        found_fields.push(item);
      };
    };
    found_fields.len() == fields.len()
  }

}

