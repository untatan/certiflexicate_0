

// random

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



use rand::{
  RngCore,
  rngs::{
    OsRng,
  },
};

use super::{
  base64::{
    get_urlsafe_string,
  },
};


pub(
    in super::super
) fn get_random_bytes_as_string(b: u8) -> String {
  let mut buffer = vec![0; b.into()];
  //∵ OsRng.fill(&mut buffer); // for length 32
  OsRng.fill_bytes(&mut buffer);
  get_urlsafe_string(&buffer)
}


#[cfg(test)]
mod tests {

  use super::{
    super::{
      base64::{
        get_base64_decoded,
      },
    },
    get_random_bytes_as_string
  };


  #[test]
  fn test_02() {
    let s = get_random_bytes_as_string(32);
    //println!("random string: {:?}", s);
    //println!("random string length: {:?}", s.len());
    //println!("random string bytes: {:?}", s.as_bytes());
    //println!("random string bytes length : {:?}", s.as_bytes().len());
    assert!(get_base64_decoded(&s).is_ok());
  }
  
  #[test]
  fn test_03() {
    let s = get_random_bytes_as_string(36);
    //println!("random string: {:?}", s);
    //println!("random string length: {:?}", s.len());
    //println!("random string bytes: {:?}", s.as_bytes());
    //println!("random string bytes length : {:?}", s.as_bytes().len());
    assert!(get_base64_decoded(&s).is_ok());
  }

}

