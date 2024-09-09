

// base64

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



use base64::{
  alphabet::{
    URL_SAFE as alphabet_URL_SAFE,
  },
  engine::{
    general_purpose::{
      URL_SAFE,
    },
    Engine,
  },
};

use crate::{
  flexicate::{
    error::{
      ErrorCertiflexicate,
    },
  },
};


pub(
    in super::super
) fn get_urlsafe_string(buffer: &[u8]) -> String {
  URL_SAFE.encode(buffer)
}

pub(
    in super::super
) fn all_chars_urlsafe(s: &str) -> bool {
  let mut breaked = false;
  for item in s.chars() {
    if !alphabet_URL_SAFE.as_str().contains(item) && item != '=' {
      breaked = true;
      break;
    };
  };
  !breaked
}

pub(
    in super::super
) fn get_base64_decoded(
    s: &str,
) -> Result<
    Vec<u8>,
    ErrorCertiflexicate,
> {
  URL_SAFE
      .decode(s)
      .map_err(
          |e| ErrorCertiflexicate::base64_err(
              &e.to_string(),
          )
      )
}



#[cfg(test)]
mod tests {

  use super::{
    all_chars_urlsafe,
  };
  
  #[test]
  fn all_chars_urlsafe_001() {
    assert!(all_chars_urlsafe(""))
  }
  
  #[test]
  fn all_chars_urlsafe_002() {
    assert!(!all_chars_urlsafe(" "))
  }
  
  #[test]
  fn all_chars_urlsafe_003() {
    assert!(all_chars_urlsafe("="))
  }
  
  #[test]
  fn all_chars_urlsafe_004() {
    assert!(all_chars_urlsafe("=="))
  }
  
  #[test]
  fn all_chars_urlsafe_005() {
    assert!(all_chars_urlsafe(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=",
    ))
  }
  
  #[test]
  fn all_chars_urlsafe_006() {
    assert!(!all_chars_urlsafe("ab/cd"))
  }
  
  #[test]
  fn all_chars_urlsafe_007() {
    assert!(!all_chars_urlsafe("ab\\cd"))
  }
  
  #[test]
  fn all_chars_urlsafe_008() {
    assert!(!all_chars_urlsafe("ab*cd"))
  }
  
  #[test]
  fn all_chars_urlsafe_009() {
    assert!(!all_chars_urlsafe("ab+cd"))
  }
  
  #[test]
  fn all_chars_urlsafe_010() {
    assert!(!all_chars_urlsafe("abcdä"))
  }
  
  #[test]
  fn all_chars_urlsafe_011() {
    assert!(!all_chars_urlsafe("ab cd"))
  }
  
  #[test]
  fn all_chars_urlsafe_012() {
    assert!(all_chars_urlsafe("123"))
  }

}

