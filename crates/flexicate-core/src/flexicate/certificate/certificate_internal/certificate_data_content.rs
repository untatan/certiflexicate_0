

// certificate_data_content

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
  super::{
    signatures::{
      signatures_signable_data::{
        DataFields,
      },
    },
  },
};


/// What may be additionally included in and signed by a certiflexicate.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum DataContent {
  /// Custom non empty data.
  Bytes(Vec<u8>),
}


impl DataContent {

  pub(super) fn get_data_field_for_data_content(&self) -> DataFields {
    match self {
      DataContent::Bytes(_) => DataFields::Bytes,
    }
  }

}

