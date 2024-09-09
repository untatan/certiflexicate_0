

// signatures_accepted

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
};


/// `SignatureData` depending on the availability of the
/// accept state of the signature.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum SignatureAccepted {
  /// signature is not accepted
  NotAccepted(SignatureData),
  /// signature is created with key of this certiflexicate and
  /// automatically accepted if not deleted
  AcceptedSelf(SignatureData),
  /// signature is created with key from other certiflexicate and
  /// later accepted by key of this certiflexicate
  Accepted(SignatureData),
}

