

// signature_fields

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



pub(super) mod field_types;


//∵ at least these
pub(super) const SIGNATURESFIELD_DEFAULT_001: &str = "flexicate";

pub(super) const SIGNATURESFIELD_SIGNATUREDATA_001: &str = "signature_data";

const SIGNATURESFIELD_PUBLICSIGNINGKEY_001: &str = "public_signing_key";

//∵ additionally these
const SIGNATURESFIELD_BYTECONTENT_001: &str = "byte_content";
// TODO extend on new fields


pub(super) const KNOWNSIGNATURESFIELDS: [&str; 4] = [
    SIGNATURESFIELD_DEFAULT_001,
    SIGNATURESFIELD_SIGNATUREDATA_001,
    SIGNATURESFIELD_PUBLICSIGNINGKEY_001,
    SIGNATURESFIELD_BYTECONTENT_001,
    // TODO extend on new fields
];


//∵ better to grep
#[allow(clippy::enum_variant_names)]
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub(super) enum CertiflexicateFieldTypes {
  CertiflexicateIdentifier,
  CertiflexicateVersion,
  CertiflexicatePublicKey,
  CertiflexicateByteContent,
  CertiflexicateSignatureData,
  // TODO extend on new fields
}

