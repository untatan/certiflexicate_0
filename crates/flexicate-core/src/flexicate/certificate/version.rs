

// version

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
    error::{
      ErrorCertiflexicate
    },
  },
};


pub(super) const LASTVERSION: u32 = 1;

const KNOWNVERSIONS: [u32; 1] = [1];

const VERSIONSDEPRECATED: [u32; 0] = [];


impl Certiflexicate {

  pub(super) fn check_if_valid_version(
      &self,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    check_if_valid_version(self.version)
  }

}


pub(super) fn check_if_valid_version(
    version: u32,
) -> Result<
    (),
    ErrorCertiflexicate,
> {
  if version > 0 {
    if version <= LASTVERSION {
      if KNOWNVERSIONS.contains(&version) {
        if !VERSIONSDEPRECATED.contains(&version) {
          Ok(())
        } else {
          Err(ErrorCertiflexicate::invalid_cert_err("deprecated version"))
        }
      } else {
        Err(ErrorCertiflexicate::invalid_cert_err("unknown version"))
      }
    } else {
      Err(ErrorCertiflexicate::invalid_cert_err("high version"))
    }
  } else {
    Err(ErrorCertiflexicate::invalid_cert_err("low version"))
  }
}


#[cfg(test)]
mod tests {

  use super::{
    Certiflexicate,
    LASTVERSION,
  };


  #[test]
  fn version_is_0() {
    let c = Certiflexicate::get_defaults();
    assert!(c.check_if_valid_version().is_err());
  }

  #[test]
  fn version_is_current() {
    let mut c = Certiflexicate::get_defaults();
    c.version = LASTVERSION;
    assert!(c.check_if_valid_version().is_ok());
  }
  
  #[test]
  fn version_is_previous() {
    let mut c = Certiflexicate::get_defaults();
    if LASTVERSION > 1 {
      c.version = LASTVERSION - 1;
    } else {
      c.version = LASTVERSION;
    };
    assert!(c.check_if_valid_version().is_ok());
  }

  #[test]
  fn version_is_unreleased() {
    let mut c = Certiflexicate::get_defaults();
    c.version = LASTVERSION + 1;
    assert!(c.check_if_valid_version().is_err());
  }

  #[test]
  fn version_is_1() {
    let mut c = Certiflexicate::get_defaults();
    c.version = 1;
    assert!(c.check_if_valid_version().is_ok());
  }

  #[test]
  fn version_is_2() {
    let mut c = Certiflexicate::get_defaults();
    c.version = 2;
    assert!(c.check_if_valid_version().is_err());
  }

  #[test]
  fn version_is_3() {
    let mut c = Certiflexicate::get_defaults();
    c.version = 3;
    assert!(c.check_if_valid_version().is_err());
  }

}

