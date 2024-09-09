

// error

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
  error::Error as std_error_Error,
  fmt::{
    Display as std_fmt_Display,
    Formatter as std_fmt_Formatter,
    Result as std_fmt_Result,
  },
};


/// Errors produced by this crate.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorCertiflexicate {
  /// Signature accept did not happen.
  AcceptingSignature(String),
  /// Adding data did not happen.
  AddingData(String),
  /// Secret key not attached.
  AttachSecretKey(String),
  /// Base64 decoding or encoding.
  Base64(String),
  /// Can not build with the provided data.
  Building(String),
  /// Todo.
  Catch(String),
  /// Chrono.
  Chrono(String),
  /// Not created.
  CreateNew(String),
  /// Serialized data failed to fit into deserialized container.
  DeserializeData(String),
  /// Ed25519Dalek.
  Ed25519Dalek(String),
  /// Could not get data.
  GettingData(String),
  /// Regex.
  Regex(String),
  /// Signing does not work currently.
  SigningData(String),
  /// Certiflexicate seems to be invalid.
  ValidatingCertiflexicate(String),
  /// Provided data seems to be invalid.
  ValidatingData(String),
  /// PublicKeyInfo seems to be invalid.
  ValidatingPublicKeyInfo(String),
  /// SignatureData seems to be invalid.
  ValidatingSignature(String),
  /// Verify signature does not work currently.
  VerifySignature(String),
}


impl std_fmt_Display for ErrorCertiflexicate {

  fn fmt(&self, f: &mut std_fmt_Formatter<'_>) -> std_fmt_Result {
    let (s1, s2) = match self {
      ErrorCertiflexicate::AcceptingSignature(s) => {
        ("AcceptingSignature", s)
      },
      ErrorCertiflexicate::AddingData(s) => {
        ("AddingData", s)
      },
      ErrorCertiflexicate::AttachSecretKey(s) => {
        ("AttachSecretKey", s)
      },
      ErrorCertiflexicate::Base64(s) => {
        ("Base64", s)
      },
      ErrorCertiflexicate::Building(s) => {
        ("Building", s)
      },
      ErrorCertiflexicate::Chrono(s) => {
        ("Chrono", s)
      },
      ErrorCertiflexicate::Catch(s) => {
        ("Catch", s)
      },
      ErrorCertiflexicate::CreateNew(s) => {
        ("CreateNew", s)
      },
      ErrorCertiflexicate::DeserializeData(s) => {
        ("DeserializeData", s)
      },
      ErrorCertiflexicate::Ed25519Dalek(s) => {
        ("Ed25519Dalek", s)
      },
      ErrorCertiflexicate::GettingData(s) => {
        ("GettingData", s)
      },
      ErrorCertiflexicate::Regex(s) => {
        ("Regex", s)
      },
      ErrorCertiflexicate::SigningData(s) => {
        ("SigningData", s)
      },
      ErrorCertiflexicate::ValidatingCertiflexicate(s) => {
        ("ValidatingCertiflexicate", s)
      },
      ErrorCertiflexicate::ValidatingData(s) => {
        ("ValidatingData", s)
      },
      ErrorCertiflexicate::ValidatingPublicKeyInfo(s) => {
        ("ValidatingPublicKeyInfo", s)
      },
      ErrorCertiflexicate::ValidatingSignature(s) => {
        ("ValidatingSignature", s)
      },
      ErrorCertiflexicate::VerifySignature(s) => {
        ("VerifySignature", s)
      },
    };
    write!(f, "ErrorCertiflexicate - {} : {}", s1, s2)
  }

}


impl std_error_Error for ErrorCertiflexicate {
 
  //fn source(&self) -> Option<&(dyn std_error_Error + 'static)> {
  //    Some(&self.source)
  //}

}


impl ErrorCertiflexicate {

  pub(super) fn accepting_sig(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::AcceptingSignature(s.to_string())
  }

  pub(super) fn adding_data(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::AddingData(s.to_string())
  }

  pub(super) fn attach_skey(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::AttachSecretKey(s.to_string())
  }

  pub(super) fn base64_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::Base64(s.to_string())
  }

  pub(super) fn building(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::Building(s.to_string())
  }

  pub(super) fn chrono_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::Chrono(s.to_string())
  }

  pub(super) fn catch_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::Catch(s.to_string())
  }

  pub(super) fn create_cert(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::CreateNew(s.to_string())
  }

  pub(super) fn deserializing_data(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::DeserializeData(s.to_string())
  }

  pub(super) fn ed25519_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::Ed25519Dalek(s.to_string())
  }

  pub(super) fn getting_data(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::GettingData(s.to_string())
  }

  pub(super) fn regex_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::Regex(s.to_string())
  }

  pub(super) fn signable_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::SigningData(s.to_string())
  }

  pub(super) fn invalid_cert_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::ValidatingCertiflexicate(s.to_string())
  }

  pub(super) fn invalid_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::ValidatingData(s.to_string())
  }

  pub(super) fn invalid_pk_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::ValidatingPublicKeyInfo(s.to_string())
  }

  pub(super) fn invalid_sig_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::ValidatingSignature(s.to_string())
  }

  pub(super) fn verify_sig_err(s: &str) -> ErrorCertiflexicate {
    ErrorCertiflexicate::VerifySignature(s.to_string())
  }

}

