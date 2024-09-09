

// signatures_verify_states

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



//∵ TODO implement and use more variants
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub(in super::super) enum VerifyState {
  NoInfo,
  VerifyFailure,
  #[allow(dead_code)]
  CheckFailure,
  Verified,
  #[allow(dead_code)]
  Checked,
  VerifiedAndChecked,
  SignatureCreated,
}


const VERIFYSTATESVERIFIED: [VerifyState; 3] = [
    VerifyState::Verified,
    VerifyState::VerifiedAndChecked,
    VerifyState::SignatureCreated,
];

impl VerifyState {

  pub(
      super
  ) fn get_default() -> VerifyState {
    VerifyState::NoInfo
  }
  
  pub(
      in super::super
  ) fn get_verified_states() -> &'static [VerifyState; 3] {
    &VERIFYSTATESVERIFIED
  }

}

