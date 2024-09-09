

// certificate_deserialize

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



use std::{
  collections::HashMap as std_collections_HashMap,
};

use super::{
  Certiflexicate,
  CertiflexicateSerial,
  ErrorCertiflexicate,
  PublicKeyInfo,
  super::{
    RegexHelpers,
  },
};


impl TryFrom<CertiflexicateSerial> for Certiflexicate {

  type Error = ErrorCertiflexicate;

  fn try_from (
      c: CertiflexicateSerial,
  ) -> Result<
      Certiflexicate,
      Self::Error,
  > {
    let regexes = RegexHelpers::get_compiled()?;
    let public_key_info = if 
        c.public_signing_key == PublicKeyInfo::get_not_useable_default()
    {
      None
    } else {
      Some(c.public_signing_key)
    };
    let byte_content = if !c.byte_content.is_empty() {
      Some(c.byte_content)
    } else {
      None
    };
    let signatures = if c.signatures.is_empty() {
      None
    } else {
      let mut hm = std_collections_HashMap::with_capacity(
          c.signatures.len() + 1,
      );
      for (k, mut v) in c.signatures.into_iter() {
        v.seems_valid_after_load_in_cert(
            &k,
            &public_key_info,
            regexes.get_regex_date(),
        )?;
        hm.insert(k, v);
      };
      Some(hm)
    };
    let cf = Certiflexicate {
      certiflexicate: c.certiflexicate,
      version: c.version,
      byte_content: byte_content,
      public_key_info: public_key_info,
      signatures: signatures,
      all_signatures_visited_once: false,
      regexes: Some(regexes),
    };
    cf.inital_validation_checks()
  }

}

