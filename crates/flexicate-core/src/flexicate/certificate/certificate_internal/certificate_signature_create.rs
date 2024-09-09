

// certificate_signature_create

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
  ErrorCertiflexicate,
  PublicKeyInfo,
  SignatureData,
  super::{
    signatures::{
      signatures_signable_data::{
        DataFields,
      },
    },
  },
};


impl Certiflexicate {

  fn check_if_data_available_for_fields(
      &self,
      fields: &Vec<CertiflexicateFieldTypes>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let mut s_th_missing = false;
    for item in fields {
      s_th_missing = match item {
        CertiflexicateFieldTypes::CertiflexicateIdentifier => false,
        CertiflexicateFieldTypes::CertiflexicateVersion => false,
        CertiflexicateFieldTypes::CertiflexicatePublicKey => {
            self.public_key_info.is_none()
        },
        CertiflexicateFieldTypes::CertiflexicateByteContent => {
            self.byte_content.is_none()
        },
        CertiflexicateFieldTypes::CertiflexicateSignatureData => {
            self.signatures.is_none()
        },
      };
      if s_th_missing {
        break;
      };
    };
    if s_th_missing {
      Err(ErrorCertiflexicate::signable_err(
          "missing data",
      ))
    } else {
      Ok(())
    }
  }

}


fn create_signature_from_cert(
    cert: &Certiflexicate,
    pk: &PublicKeyInfo,
    extended_to: &[DataFields],
) -> Result<
    SignatureData,
    ErrorCertiflexicate,
> {
  let fields = CertiflexicateFieldTypes
      ::get_necessary_fields_and_signables(extended_to)
  ;
  cert.check_if_data_available_for_fields(&fields)?;
  if pk.has_secret_key_data() {
    if cert.signatures.is_some() {
      SignatureData::create_signed_signature(pk, cert, fields)
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "no signatures",
      ))
    }
  } else {
    Err(ErrorCertiflexicate::signable_err(
        "no secret key",
    ))
  }
}


fn add_signature_to_cert(
    cert: &mut Certiflexicate,
    signature_result: Result<
        SignatureData,
        ErrorCertiflexicate,
    >,
) -> Result<
    SignatureData,
    ErrorCertiflexicate,
> {
  if let Ok(sig) = signature_result {
    if let Some(ref mut signatures) = cert.signatures{
      let nonce = sig.get_nonce_string();
      #[allow(clippy::map_entry)]
      if !signatures.contains_key(&nonce) {
        let sig_iso = sig.clone_isolated();
        signatures.insert(nonce, sig);
        Ok(sig_iso)
      } else {
        Err(ErrorCertiflexicate::signable_err(
            "nonce doubled",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "again no signatures",
      ))
    }
  } else {
    signature_result
  }
}


impl Certiflexicate {

  pub(
      super
  ) fn create_and_add_self_signed_signature_to_this_cert(
      &mut self,
      extended_to: &[DataFields],
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    let pk = self.get_public_key_info_ref()?;
    add_signature_to_cert(
        self,
        create_signature_from_cert(
            self,
            pk,
            extended_to,
        )
    )
  }

  pub(
      super
  ) fn create_and_add_signed_signature_to_other_cert(
      &self,
      cert: &mut Certiflexicate,
      extended_to: &[DataFields],
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    let pk = self.get_public_key_info_ref()?;
    if cert.public_key_info.is_some()
        && cert.signatures.is_some()
    {
      add_signature_to_cert(
          cert,
          create_signature_from_cert(
              cert,
              pk,
              extended_to,
          )
      )
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "missing data in other certiflexicate",
      ))
    }
  }

  pub(
      super
  ) fn accept_a_signature_in_this_cert(
      &mut self,
      sig: &SignatureData,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    self.verify_the_unverified_signatures()?;
    if let Some(ref pk) = self.public_key_info {
      if pk.has_secret_key_data() {
        if let Some(ref mut signatures) = self.signatures{
          let nonce = sig.get_nonce_string();
          if let Some(signature) = signatures.get_mut(&nonce) {
            if sig.signatures_equal_wo_isolation(signature) {
              if signature.get_accept_state().state_is_not_accepted() {
                let old_accept = signature.get_accepted_base64().to_string();
                let created = signature.accept_the_signature_with_key(pk);
                if let Ok(
                    asig_string
                ) = created {
                  if !asig_string.is_empty()
                      && asig_string == signature.get_accepted_base64()
                      && old_accept != signature.get_accepted_base64()
                  {
                    if !signature.signatures_equal_wo_isolation(sig) {
                      Ok(())
                    } else {
                      Err(ErrorCertiflexicate::accepting_sig(
                          "signature unchanged",
                      ))
                    }
                  } else {
                    Err(ErrorCertiflexicate::accepting_sig(
                        "created signature bogus",
                    ))
                  }
                } else if let Err(e) = created {
                  Err(e)
                } else {
                  Err(ErrorCertiflexicate::accepting_sig(
                      "not ok and not error?",
                  ))
                }
              } else {
                Err(ErrorCertiflexicate::accepting_sig(
                    "signature was accepted previously",
                ))
              }
            } else {
              Err(ErrorCertiflexicate::accepting_sig(
                  "signatures not equal",
              ))
            }
          } else {
            Err(ErrorCertiflexicate::accepting_sig(
                "not found in signatures",
            ))
          }
        } else {
          Err(ErrorCertiflexicate::accepting_sig(
              "no signatures",
          ))
        }
      } else {
        Err(ErrorCertiflexicate::accepting_sig(
            "no secret key",
        ))
      }
    } else {
      Err(ErrorCertiflexicate::accepting_sig(
          "no public key",
      ))
    }
  }

}

