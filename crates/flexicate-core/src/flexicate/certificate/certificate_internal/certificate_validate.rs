

// certificate_validate

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
  CertiflexicateFieldTypes,
  CERTIFLEXICATEIDENTIFIER,
  ErrorCertiflexicate,
};


impl Certiflexicate {

  fn check_if_valid_id(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.certiflexicate == CERTIFLEXICATEIDENTIFIER {
      Ok(())
    } else {
      Err(ErrorCertiflexicate::invalid_cert_err("identifier"))
    }
  }

  fn no_signed_field_for_uncovered_data_fields(
      &self,
      vect: &[CertiflexicateFieldTypes],
  ) -> bool {
    let mut uncovered_found = 0;
    if let Some(ref sigs) = self.signatures {
      let mut found_uncovered = Vec::new();
      for val in sigs.values() {
        for item in val.get_claimed_fields() {
          if !vect.contains(item) && !found_uncovered.contains(item) {
            found_uncovered.push(item.clone());
          };
        };
      };
      uncovered_found = found_uncovered.len();
    } else {
      uncovered_found += 1;
    };
    uncovered_found == 0
  }

  fn all_data_fields_have_self_signature(
      &self,
      vect: &Vec<CertiflexicateFieldTypes>
  ) -> bool {
    let mut self_signed_fields = Vec::with_capacity(vect.len());
    if let Some(ref pk) = self.public_key_info {
      //∵ unmutable signatures because cert borrowed
      if let Some(ref sigs) = self.signatures {
        for val in sigs.values() {
          if let Some(
              fields
          ) = val.get_self_signed_fields_once_at_load(pk) {
            for item in &fields {
              if !self_signed_fields.contains(item) {
                self_signed_fields.push(item.clone());
              };
            };
          };
        };
      };
    };
    let mut sth_not_found = 0;
    if self_signed_fields.len() == vect.len() {
      for item in &self_signed_fields {
        if !vect.contains(item) {
          sth_not_found += 2;
        };
      };
      for item in vect {
        if !self_signed_fields.contains(item) {
          sth_not_found += 3;
        };
      };
    } else {
      sth_not_found = 1;
    }
    sth_not_found == 0
  }

  fn is_very_simple_empty_cert(
      &self,
      we_need_self_signatures_for_ln: usize,
  ) -> bool {
    we_need_self_signatures_for_ln == 2
        && self.public_key_info.is_none()
        && self.signatures.is_none()
  }

  fn check_for_not_self_signed_data_and_uncovered_signatures_once_at_load(
      mut self,
  ) -> Result<
      Certiflexicate,
      ErrorCertiflexicate,
  > {
    let we_need_self_signatures_for = self.known_fields_that_have_data();
    let we_need_self_signatures_for_len = we_need_self_signatures_for.len();
    if self.is_very_simple_empty_cert(
        we_need_self_signatures_for_len,
    ) {
      Ok(self)
    } else if self.public_key_info.is_none() {
      Err(ErrorCertiflexicate::invalid_err(
          "public key not found",
      ))
    } else if self.signatures.is_none() {
      Err(ErrorCertiflexicate::invalid_err(
          "no signature found",
      ))
    } else {
      self.verify_the_unverified_signatures()?;
      if we_need_self_signatures_for_len > 2 {
        if !self.no_signed_field_for_uncovered_data_fields(
            &we_need_self_signatures_for,
        ) {
          Err(ErrorCertiflexicate::invalid_err(
              "signature for unavailable data",
          ))
        } else if !self.all_data_fields_have_self_signature(
            &we_need_self_signatures_for,
        ) {
          Err(ErrorCertiflexicate::invalid_err(
              "data not self signed by public key",
          ))
        } else {
          Ok(self)
        }
      } else {
        Err(ErrorCertiflexicate::invalid_err(
            "self signature searching failure",
        ))
      }
    }
  }

  fn validate_public_key_in_cert(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if let Some(pk) = &self.public_key_info {
      pk.seems_valid_minimum()
    } else if self.signatures.is_none() {
      //∵ this is probably a certiflexicate just with the header
      //∵ checked in
      //∵ check_for_not_self_signed_data_and_uncovered_signatures_once_at_load
      Ok(())
    } else {
      Err(
          ErrorCertiflexicate::invalid_err(
              "public key not found in certiflexicate",
          )
      )
    }
  }

}


impl Certiflexicate {

  pub(
      in super::super
  ) fn seems_valid_cert_minimum(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.check_if_valid_version()?;
    self.check_if_valid_id()
  }

  pub(super) fn inital_validation_checks(
      self,
  ) -> Result<
      Certiflexicate,
      ErrorCertiflexicate,
  > {
    if self.regexes.is_some() {
      self.seems_valid_cert_minimum()?;
      //∵ already done in public key load
      //∵ superfluous
      self.validate_public_key_in_cert()?;
      self.check_for_not_self_signed_data_and_uncovered_signatures_once_at_load(
      )
    } else {
      Err(ErrorCertiflexicate::deserializing_data(
          "regex not compiled",
      ))
    }
  }

}

