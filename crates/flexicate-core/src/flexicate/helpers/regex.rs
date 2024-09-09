

// regex

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
    error::{
      ErrorCertiflexicate,
    },
  },
};


#[derive(Clone, Debug)]
pub(in super::super) struct RegexHelpers {
  date_string_regex: Regex,
}


impl RegexHelpers {

  fn get_compiled_date_string() -> Result<
      Regex,
      ErrorCertiflexicate,
  > {
    Regex::new(
          "^2[0-9]{3}-[01][0-9]-[0-3][0-9]T[0-2][0-9](:[0-5][0-9]){2}(\\+|-)[0-2][0-9]:[0-5][0-9]$"
    ).map_err(
        |e| ErrorCertiflexicate::regex_err(
            &e.to_string(),
        )
    )
  }

}


impl RegexHelpers {

  pub(
      in super::super
  ) fn get_compiled() -> Result<
      RegexHelpers,
      ErrorCertiflexicate,
  > {
    let regex_date = RegexHelpers::get_compiled_date_string()?;
    Ok(RegexHelpers {
        date_string_regex: regex_date,
    })
  }

  pub(
      in super::super
  ) fn get_regex_date(&self) -> &Regex {
    &self.date_string_regex
  }

}



#[cfg(test)]
mod tests {

  use super::{
    RegexHelpers,
  };


  #[test]
  fn regex_date_001() {
    if let Ok(re) = RegexHelpers::get_compiled_date_string() {
      assert!(!re.is_match("1990-06-15T01:59:00-11:00"))
    } else {
      panic!()
    }
  }

  #[test]
  fn regex_date_002() {
    if let Ok(re) = RegexHelpers::get_compiled_date_string() {
      assert!(!re.is_match("3990-06-15T01:59:00+11:00"))
    } else {
      panic!()
    }
  }

  #[test]
  fn regex_date_003() {
    if let Ok(re) = RegexHelpers::get_compiled_date_string() {
      assert!(re.is_match("2190-06-15T01:59:00-00:00"))
    } else {
      panic!()
    }
  }

  #[test]
  fn regex_date_004() {
    if let Ok(re) = RegexHelpers::get_compiled_date_string() {
      assert!(re.is_match("2000-06-15T01:59:00+00:00"))
    } else {
      panic!()
    }
  }

}

