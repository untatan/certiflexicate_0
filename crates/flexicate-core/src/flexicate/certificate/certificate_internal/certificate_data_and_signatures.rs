

// certificate_data_and_signatures

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
  DataContent,
  DataFields,
  ErrorCertiflexicate,
  SignatureData,
  super::{
    signatures::{
      signatures_accepted::{
        SignatureAccepted,
      },
    },
  },
};


impl Certiflexicate {

  pub(super) fn add_data_and_create_self_signed_signature(
      &mut self,
      data: DataContent,
  ) -> Result<
      SignatureData,
      ErrorCertiflexicate,
  > {
    let field = data.get_data_field_for_data_content();
    self.try_to_add_content_data(
        data
    )?;
    let res1 = self.create_and_add_self_signed_signature_to_this_cert(
        &[field.clone()],
    );
    if let Err(e) = res1 {
      //∵ ignore delete error - main error occured before ∎
      let _ = self.try_to_delete_content_data(field);
      Err(e)
    } else {
      res1
    }
  }

  pub(super) fn get_data_for_field_with_signatures(
      &mut self,
      field: DataFields,
  ) -> Result<
      (
          DataContent,
          Vec<SignatureAccepted>,
      ),
      ErrorCertiflexicate,
  > {
    let sigs = self.get_all_verified_but_unchecked_signatures_internal(
        &[field.clone()],
    )?;
    if sigs.is_empty() {
      Err(
          ErrorCertiflexicate::getting_data(
              "no signatures found for data field",
          )
      )
    } else {
      let data = self.try_to_get_content_data(&field)?;
      Ok((data, sigs))
    }
  }

}

