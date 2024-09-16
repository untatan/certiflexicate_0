

// signatures_validator

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



use regex::Regex;

use crate::{
  flexicate::{
    helpers::{
      base64::{
        all_chars_urlsafe,
      },
      datetime::{
        get_datetime_from_string_with_regex_check,
      },
    },
  },
};

use super::{
  DEPRECATEDSIGNATUREVERSIONS,
  KNOWNSIGNATURESVERSIONS,
  LASTSIGNATURESVERSION,
  PublicKeyInfo,
  SignatureData,
  super::{
    signature_fields::{
      CertiflexicateFieldTypes,
      KNOWNSIGNATURESFIELDS,
      SIGNATURESFIELD_DEFAULT_001,
      SIGNATURESFIELD_SIGNATUREDATA_001,
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


const SIGNATURE_BASE64_LENGTH: usize = 88;

const NONCE_BASE64_LENGTH: usize = 48;


pub(
    in super::super
) fn check_if_nonce_valid(
    nonce: &str,
) -> Result<
    (),
    ErrorCertiflexicate,
> {
  if nonce.len() == NONCE_BASE64_LENGTH {
    if all_chars_urlsafe(nonce) {
      Ok(())
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err(
          "nonce invalid char",
      ))
    }
  } else {
    Err(ErrorCertiflexicate::invalid_sig_err(
        "nonce length",
    ))
  }
}


impl SignatureData {

  fn check_signature_version(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.version > 0 {
      if self.version <= LASTSIGNATURESVERSION {
        if KNOWNSIGNATURESVERSIONS.contains(&self.version) {
          if !DEPRECATEDSIGNATUREVERSIONS.contains(&self.version) {
            Ok(())
          } else {
            Err(ErrorCertiflexicate::invalid_sig_err("deprecated version"))
          }
        } else {
          Err(ErrorCertiflexicate::invalid_sig_err("unknown version"))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err("high version"))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err("low version"))
    }
  }

  fn check_signature_signed_fields_length(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.signed_fields.len() >= 3 {
      if self.signed_fields.len() <= KNOWNSIGNATURESFIELDS.len() {
        Ok(())
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err("long signed fields"))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err("few signed fields"))
    }
  }

  fn apply_signature_signed_fields_found_fields(
      &mut self,
      mut found_fields: Vec<String>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let mut claimed_signed_fields = Vec::with_capacity(found_fields.len());
    for item in found_fields.drain(..) {
      let fieldtypes = CertiflexicateFieldTypes
          ::get_fieldtype_by_known_sig_field(
              &item
          )
      ?;
      for jtem in fieldtypes {
        if !claimed_signed_fields.contains(jtem) {
          claimed_signed_fields.push(jtem.clone());
        };
      };
    };
    self.set_claimed_signed_fields(claimed_signed_fields);
    Ok(())
  }

  fn check_signature_signed_fields_content(
      &mut self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let mut has_something_unknown = false;
    let mut has_something_more_than_once = false;
    let mut missing_something_required = 0;
    let mut found_fields = Vec::with_capacity(self.signed_fields.len());
    for item in &self.signed_fields {
      if !found_fields.contains(item) {
        found_fields.push(item.clone());
        if !KNOWNSIGNATURESFIELDS.contains(&item.as_str()) {
          has_something_unknown = true;
        };
        #[allow(clippy::if_same_then_else)]
        if item == SIGNATURESFIELD_DEFAULT_001 {
          missing_something_required += 1;
        } else if item == SIGNATURESFIELD_SIGNATUREDATA_001 {
          missing_something_required += 1;
        };
      } else {
        has_something_more_than_once = true;
      };
    };
    if !has_something_unknown {
      if !has_something_more_than_once {
        if missing_something_required == 2 {
          self.apply_signature_signed_fields_found_fields(found_fields)
        } else {
          Err(ErrorCertiflexicate::invalid_sig_err(
              "missing signed field",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err(
            "signed field more than once",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err("unknown signed field"))
    }
  }

  fn check_signature_claimed_fields(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let should_be_signed_fields = get_signed_fields_strings_for_fields(
        &self.claimed_signed_fields,
    );
    if should_be_signed_fields == self.signed_fields {
      if self.claimed_signed_fields.len() >= CertiflexicateFieldTypes
          ::get_minimum_number_of_fields()
      {
        if self.claimed_signed_fields.len() <= CertiflexicateFieldTypes
            ::get_maximum_number_of_fields()
        {
          Ok(())
        } else {
          Err(ErrorCertiflexicate::invalid_sig_err(
              "high claimed signed fields",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err(
            "low claimed signed fields",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err(
          "signed fields mismatch",
      ))
    }
  }

  fn check_signature_signed_fields(
      &mut self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.check_signature_signed_fields_length()?;
    self.check_signature_signed_fields_content()?;
    self.check_signature_claimed_fields()
  }

  fn check_signature_self_signed(
      &mut self,
      pk_opt: &Option<PublicKeyInfo>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if let Some(pk) = pk_opt {
      if let Some(pubk) = &self.public_sig_key_info {
        if pk == pubk {
          self.claimed_self_signature = true;
        };
      };
    };
    Ok(())
  }

  fn check_signature_base64(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if !self.base64.is_empty() {
      if self.base64.len() == SIGNATURE_BASE64_LENGTH {
        if all_chars_urlsafe(
            &self.base64,
        ) {
          Ok(())
        } else {
          Err(ErrorCertiflexicate::invalid_sig_err(
              "signature invalid char",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err(
            "signature length",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err(
          "no signature",
      ))
    }
  }

  fn check_signature_accepted_base64(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.accepted_base64.is_empty() {
      Ok(())
    } else if self.accepted_base64.len() == SIGNATURE_BASE64_LENGTH {
      if all_chars_urlsafe(&self.accepted_base64) {
        Ok(())
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err(
            "accepted signature invalid char",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err(
          "accepted signature length",
      ))
    }
  }

  fn check_public_key(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let pk = self.get_sig_public_key_info_ref()?;
    pk.seems_valid_minimum()
  }

  fn assign_and_check_public_key_if_unuseable(
      &mut self,
      pk_opt: &Option<PublicKeyInfo>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let add_it = if let Some(pk) = &self.public_sig_key_info {
      pk.is_not_useable()
    } else {
      true
    };
    if add_it && !self.cert_has_same_public_key
    {
      if let Some(pk) = pk_opt {
        self.public_sig_key_info = Some(pk.get_pk_clone_clean());
        self.cert_has_same_public_key = true;
      };
    };
    self.check_public_key()
  }

  fn assign_and_validate_dates(
      &mut self,
      date_string_regex: &Regex,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.start_date.is_empty() && self.stop_date.is_empty() {
      Ok(())
    } else {
      let start_ok = if !self.start_date.is_empty(){
        let start = get_datetime_from_string_with_regex_check(
            &self.start_date,
            date_string_regex,
        )?;
        self.datetime_start = Some(start);
        self.datetime_start.is_some()
      } else {
        true
      };
      let stop_ok = if !self.stop_date.is_empty() {
        let stop = get_datetime_from_string_with_regex_check(
            &self.stop_date,
            date_string_regex,
        )?;
        self.datetime_stop = Some(stop);
        self.datetime_stop.is_some()
      } else {
        true
      };
      if stop_ok == start_ok && start_ok {
        if self.datetime_stop.is_some() && self.datetime_start.is_some() {
          if let Some(ref datetime_start) = self.datetime_start {
            if let Some(ref datetime_stop) = self.datetime_stop {
              if datetime_stop > datetime_start {
                Ok(())
              } else {
                Err(ErrorCertiflexicate::invalid_sig_err(
                    "start date after stop date",
                ))
              }
            } else {
              Err(ErrorCertiflexicate::invalid_sig_err(
                  "stop date failure",
              ))
            }
          } else {
            Err(ErrorCertiflexicate::invalid_sig_err(
                "start date failure",
            ))
          }
        } else {
          Ok(())
        }
      } else {
        Err(ErrorCertiflexicate::invalid_sig_err(
            "dates failure",
        ))
      }
    }
  }

}


impl SignatureData {

  pub(
      in super::super
  ) fn seems_valid_wo_nonce_and_wo_public_key(
      &mut self,
      pk_opt: &Option<PublicKeyInfo>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.check_signature_version()?;
    self.check_signature_self_signed(pk_opt)?;
    self.check_signature_signed_fields()?;
    self.check_signature_base64()?;
    self.check_signature_accepted_base64()
  }

  pub(
      in super::super
  ) fn seems_valid_wo_nonce(
      &mut self,
      pk_opt: &Option<PublicKeyInfo>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.assign_and_check_public_key_if_unuseable(pk_opt)?;
    self.seems_valid_wo_nonce_and_wo_public_key(pk_opt)
  }

  pub(
      in super::super
  ) fn seems_valid_after_load_in_cert(
      &mut self,
      nonce: &str,
      pk_opt: &Option<PublicKeyInfo>,
      date_string_regex: &Regex,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.nonce.is_empty() || nonce == self.nonce {
      check_if_nonce_valid(nonce)?;
      self.seems_valid_wo_nonce(pk_opt)?;
      self.assign_and_validate_dates(date_string_regex)?;
      if self.nonce.is_empty() {
        self.nonce = nonce.to_owned();
        Ok(())
      } else {
        check_if_nonce_valid(&self.nonce)
      }
    } else {
      Err(ErrorCertiflexicate::invalid_sig_err(
          "nonce mismatch",
      ))
    }
  }

}

