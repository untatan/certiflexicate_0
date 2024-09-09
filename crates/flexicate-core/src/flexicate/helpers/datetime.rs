

// datetime

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



use chrono::{
  DateTime as chrono_DateTime,
  offset::{
    Utc as chrono_offset_Utc,
  },
};

use regex::Regex;

use crate::{
  flexicate::{
    error::{
      ErrorCertiflexicate,
    },
  },
};


fn get_datetime_utc_from_string(
    s: &str,
) -> Result<
    chrono_DateTime<chrono_offset_Utc>,
    ErrorCertiflexicate,
> {
  let dt = chrono_DateTime::parse_from_rfc3339(s).map_err(
      |e| ErrorCertiflexicate::chrono_err(
          &e.to_string(),
      )
  )?;
  Ok(dt.naive_utc().and_utc())
}

pub(
    in super::super
) fn get_datetime_from_string_with_regex_check(
    s: &str,
    date_string_regex: &Regex,
) -> Result<
    chrono_DateTime<chrono_offset_Utc>,
    ErrorCertiflexicate,
> {
  if date_string_regex.is_match(s) {
    get_datetime_utc_from_string(s)
  } else {
    Err(ErrorCertiflexicate::regex_err(
        "datetime",
    ))
  }
}


#[cfg(test)]
mod tests {
  
  use super::{
    get_datetime_utc_from_string,
  };
  
  
  #[test]
  fn datetime_001() {
    if let Ok(dt1) = get_datetime_utc_from_string(
        "1990-06-15T12:00:00+01:00"
    ) {
      //println!("datetime 1 : {:?}", dt1);
      if let Ok(dt2) = get_datetime_utc_from_string(
          "1990-06-15T12:00:00+00:00"
      ) {
        //println!("datetime 2 : {:?}", dt2);
        assert!(dt2 > dt1);
        if let Ok(dt3) = get_datetime_utc_from_string(
            "1990-06-15T12:00:00-01:00"
        ) {
          //println!("datetime 3 : {:?}", dt3);
          assert!(dt3 > dt2);
        } else {
          panic!()
        }
      } else {
        panic!()
      }
    } else {
      panic!()
    }
  }

}

