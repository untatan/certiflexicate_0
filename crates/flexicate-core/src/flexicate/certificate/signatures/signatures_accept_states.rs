

// signatures_accept_states

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
  SignatureData,
  signatures_accepted::{
    SignatureAccepted,
  },
};


#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub(in super::super) enum AcceptState {
  NoInfo,
  NotAccepted,
  BadData,
  CheckNotPossible,
  MissingAccept,
  SelfAccepted,
  ForeignSignatureAccepted,
}


impl AcceptState {

  pub(super) fn get_default() -> AcceptState {
    AcceptState::NoInfo
  }

  pub(
      in super::super
  ) fn get_signature_accepted_info_with_signature(
      &self,
      sig: SignatureData,
  ) -> SignatureAccepted {
    match self {
      AcceptState::NoInfo => SignatureAccepted::NotAccepted(sig),
      AcceptState::NotAccepted => SignatureAccepted::NotAccepted(sig),
      AcceptState::BadData => SignatureAccepted::NotAccepted(sig),
      AcceptState::CheckNotPossible => SignatureAccepted::NotAccepted(sig),
      AcceptState::MissingAccept => SignatureAccepted::NotAccepted(sig),
      AcceptState::SelfAccepted => SignatureAccepted::AcceptedSelf(sig),
      AcceptState::ForeignSignatureAccepted => SignatureAccepted::Accepted(
          sig
      ),
    }
  }

  pub(in super::super) fn state_is_not_accepted(
      &self,
  ) -> bool {
    match self {
      AcceptState::NoInfo => true,
      AcceptState::NotAccepted => true,
      AcceptState::BadData => true,
      AcceptState::CheckNotPossible => true,
      AcceptState::MissingAccept => true,
      AcceptState::SelfAccepted => false,
      AcceptState::ForeignSignatureAccepted => false,
    }
  }

}

