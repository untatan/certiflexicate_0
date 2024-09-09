

// certificate_content

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
  super::{
    DataContent,
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
    signatures::{
      signatures_signable_data::{
        DataFields,
      },
    },
  },
};


impl Certiflexicate {

  pub(super) fn try_to_add_content_data(
      &mut self,
      data: DataContent,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    if self.signatures.is_none() {
      Err(ErrorCertiflexicate::adding_data("no signatures"))
    } else if self.public_key_info.is_none() {
      Err(ErrorCertiflexicate::adding_data("no public key"))
    } else {
      let pk = self.get_public_key_info_ref()?;
      if !pk.has_secret_key_data() {
        Err(ErrorCertiflexicate::adding_data("no secret key"))
      } else {
        match data {
          DataContent::Bytes(v) => {
            if self.byte_content.is_some() {
              Err(ErrorCertiflexicate::adding_data(
                  "existing bytes",
              ))
            } else if v.is_empty() {
              Err(ErrorCertiflexicate::adding_data(
                  "no bytes provided",
              ))
            } else {
              self.byte_content = Some(v);
              Ok(())
            }
          }
        }
      }
    }
  }

  pub(super) fn try_to_delete_content_data(
      &mut self,
      field: DataFields,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    match field {
      DataFields::Bytes => {
        if self.byte_content.is_some() {
          self.byte_content = None;
          Ok(())
        } else {
          Err(ErrorCertiflexicate::adding_data(
              "no bytes to delete",
          ))
        }
      },
    }
  }

  pub(super) fn try_to_get_content_data(
      &self,
      field: &DataFields,
  ) -> Result<
      DataContent,
      ErrorCertiflexicate,
  > {
    match field {
      DataFields::Bytes => {
        if let Some(data) = &self.byte_content {
          Ok(DataContent::Bytes(data.clone()))
        } else {
          Err(ErrorCertiflexicate::getting_data(
              "no bytes found",
          ))
        }
      },
    }
  }

}

