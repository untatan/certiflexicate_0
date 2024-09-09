

// certificate_signature_verify

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
  ErrorCertiflexicate,
  SignatureData,
  super::{
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
      signatures_verify_states::{
        VerifyState,
      },
      
    },
  },
};


impl Certiflexicate {

  fn do_the_verification_of_signature(
      &mut self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let mut ret = Ok(());
    let mut to_set = Vec::new();
    if let Some(ref pk) = self.public_key_info {
      //∵ unmutable signatures
      if let Some(ref sigs) = self.signatures {
        for (nonce, sig) in sigs.iter() {
          let new_state_opt = sig.verify_not_previously_examined_signature(
              self,
              pk,
          )?;
          if let Some(new_state) = new_state_opt {
            to_set.push((nonce.clone(), new_state));
          };
        };
      } else {
        ret = Err(
            ErrorCertiflexicate::verify_sig_err(
                "missing signatures in certiflexicate",
            )
        );
      };
      if !to_set.is_empty() && ret.is_ok() {
        //∵ mutable signatures
        if let Some(ref mut sigs) = self.signatures {
          for item in to_set {
            if let Some(sig) = sigs.get_mut(&item.0) {
              sig.set_new_verification_state(
                  pk,
                  item.1.0,
                  item.1.1,
                  item.1.2,
              )?;
            } else {
              ret = Err(
                  ErrorCertiflexicate::verify_sig_err(
                      "a missing signatures in certiflexicate",
                  )
              );
            };
            if ret.is_err() {
              break;
            };
          };
        } else {
          ret = Err(
              ErrorCertiflexicate::verify_sig_err(
                  "missing mutable signatures in certiflexicate",
              )
          )
        };
      };
    } else {
      ret = Err(
          ErrorCertiflexicate::verify_sig_err(
              "missing public key in certiflexicate",
          )
      )
    };
    ret
  }

  fn get_all_unchecked_but_verified_signatures(
      &mut self,
      fields: &[CertiflexicateFieldTypes],
  ) -> Result<
      Vec<&SignatureData>,
      ErrorCertiflexicate,
  > {
    if let Some(ref sigs) = self.signatures {
      let mut ret = Vec::new();
      let states = VerifyState::get_verified_states();
      for (_nonce, sig) in sigs.iter() {
        if sig.is_verified_state_one_of(states)
            && sig.is_verified_for_all_of(fields)
        {
          ret.push(sig);
        };
      };
      Ok(ret)
    } else {
      Err(
          ErrorCertiflexicate::verify_sig_err(
              "missing the signatures in certiflexicate",
          )
      )
    }
  }

}


fn get_signatures_in_accepted_enum(
    mut sigs: Vec<&SignatureData>,
) -> Vec<SignatureAccepted> {
  sigs
      .drain(..)
      .map(
          |sig| sig
              .get_accept_state()
              .get_signature_accepted_info_with_signature(
                  sig.clone_isolated(),
              )
      ).collect()
}


impl Certiflexicate {

  pub(super) fn verify_the_unverified_signatures(
      &mut self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if !self.all_signatures_visited_once {
      self.all_signatures_visited_once = true;
      self.do_the_verification_of_signature()
    } else {
      Ok(())
    }
  }

  pub(super) fn get_all_verified_but_unchecked_signatures_internal(
      &mut self,
      limited_to: &[DataFields],
  ) -> Result<
      Vec<SignatureAccepted>,
      ErrorCertiflexicate,
  > {
    self.verify_the_unverified_signatures()?;
    let sig_fields = CertiflexicateFieldTypes
        ::get_necessary_fields_and_signables(limited_to)
    ;
    let signatures = self.get_all_unchecked_but_verified_signatures(
        &sig_fields,
    )?;
    Ok(get_signatures_in_accepted_enum(signatures))
  }

}

