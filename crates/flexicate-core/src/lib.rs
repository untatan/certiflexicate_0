

// flexicate-core

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



#![doc(html_no_source)]
#![warn(missing_docs)]

//! # flexicate-core
//!
//! Tries to provide core data types for certiflexicates.
//!
//! If you do not know better, it is best to assume everything is
//! pre-alpha, buggy, unreliable, unstable, untested, unreviewed,
//! unsupported, unuseable and insecure.
//!
#![doc = include_str!("../../../README.md")]


mod flexicate;


pub use flexicate::{
  certificate::{
    Certiflexicate,
    CertiflexicateBuilder,
    DataContent,
    DataFields,
    PublicKeyInfo,
    SignatureAccepted,
    SignatureData,
  },
  error::{
    ErrorCertiflexicate,
  },
};

