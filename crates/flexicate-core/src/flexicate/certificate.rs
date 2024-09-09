

// certificate

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

use serde::{
  Deserialize,
  Serialize,
};


mod api;
mod certificate_internal;
mod public_key;
mod secret_key;
mod signatures;
mod signature_fields;
mod version;

#[cfg(test)]
mod testing;


pub use certificate_internal::{
  certiflexicate_builder::{
    CertiflexicateBuilder,
  },
  certificate_data_content::{
    DataContent,
  },
};

pub use public_key::{
  PublicKeyInfo,
};

pub use signatures::{
  SignatureData,
  signatures_accepted::{
    SignatureAccepted,
  },
  signatures_signable_data::{
    DataFields,
  },
};

use crate::{
  flexicate::{
    helpers::{
      regex::{
        RegexHelpers,
      },
    },
  },
};

use certificate_internal::{
  certificate_serial::{
    CertiflexicateSerial,
  },
};


/// The core struct `Certiflexicate` is a certiflexicate.
///
/// May be stored in or loaded from formats implementing serde.
///
/// Serialized, it can be shared with others, while a
/// deserialized certiflexicate may include secret key data
/// and should not be exposed to untrusted entities or code.
#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default = "Certiflexicate::get_defaults")]
#[serde(try_from = "CertiflexicateSerial")]
#[serde(into = "CertiflexicateSerial")]
pub struct Certiflexicate {
  certiflexicate: String,
  version: u32,
  byte_content: Option<Vec<u8>>,
  public_key_info: Option<PublicKeyInfo>,
  signatures: Option<std_collections_HashMap<
      String,
      SignatureData,
  >>,
  #[serde(skip)]
  all_signatures_visited_once: bool,
  #[serde(skip)]
  regexes: Option<RegexHelpers>
}


impl PartialEq for Certiflexicate {

  fn eq(&self, other: &Certiflexicate) -> bool {
    self.certiflexicate == other.certiflexicate
        && self.version == other.version
        && self.byte_content == other.byte_content
        && self.public_key_info == other.public_key_info
        && self.signatures == other.signatures
        && self.all_signatures_visited_once == other.all_signatures_visited_once
        //∵ TODO regexes and perhaps more
  }

}

