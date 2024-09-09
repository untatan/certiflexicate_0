

// field_types

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



use std::cmp::{
  Ordering as std_cmp_Ordering,
};

use super::{
  super::{
    signatures::{
      signatures_signable_data::{
        DataFields,
      },
    },
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
  },
};

use super::{
  CertiflexicateFieldTypes,
  SIGNATURESFIELD_DEFAULT_001,
  SIGNATURESFIELD_SIGNATUREDATA_001,
  SIGNATURESFIELD_PUBLICSIGNINGKEY_001,
  SIGNATURESFIELD_BYTECONTENT_001,
};


impl CertiflexicateFieldTypes {

  pub(
      in super::super
  ) fn get_fieldtype_by_known_sig_field(
      s: &str,
  ) -> Result<
      &[CertiflexicateFieldTypes],
      ErrorCertiflexicate,
  > {
    match s {
        SIGNATURESFIELD_DEFAULT_001 => Ok(&[
            CertiflexicateFieldTypes::CertiflexicateIdentifier,
            CertiflexicateFieldTypes::CertiflexicateVersion,
        ]),
        SIGNATURESFIELD_PUBLICSIGNINGKEY_001 => Ok(&[
            CertiflexicateFieldTypes::CertiflexicatePublicKey,
        ]),
        SIGNATURESFIELD_BYTECONTENT_001 => Ok(&[
            CertiflexicateFieldTypes::CertiflexicateByteContent,
        ]),
        SIGNATURESFIELD_SIGNATUREDATA_001 => Ok(&[
            CertiflexicateFieldTypes::CertiflexicateSignatureData,
        ]),
        // TODO extend on new fields
        _ => Err(
            ErrorCertiflexicate::invalid_sig_err(
                "unknown field type",
            )
        ),
    }
  }

  pub(in super::super) fn get_minimum_number_of_fields() -> usize {4}

  // TODO extend on new fields
  pub(in super::super) fn get_maximum_number_of_fields() -> usize {5}

}


pub(
    in super::super
) fn get_signed_fields_strings_for_fields(
    v: &Vec<CertiflexicateFieldTypes>,
) -> Vec<String> {
  let mut signed_fields = Vec::with_capacity(v.len());
  let mut default_found = "";
  for item in v {
    let opt = match item {
        CertiflexicateFieldTypes::CertiflexicateIdentifier => {
          if default_found.is_empty() {
            default_found ="identifier";
            None
          } else if default_found == "version" {
            default_found ="both";
            Some(SIGNATURESFIELD_DEFAULT_001.to_string())
          } else {
            None
          }
        },
        CertiflexicateFieldTypes::CertiflexicateVersion => {
          if default_found.is_empty() {
            default_found ="version";
            None
          } else if default_found == "identifier" {
            default_found ="both";
            Some(SIGNATURESFIELD_DEFAULT_001.to_string())
          } else {
            None
          }
        },
        CertiflexicateFieldTypes::CertiflexicatePublicKey =>
          Some(SIGNATURESFIELD_PUBLICSIGNINGKEY_001.to_string())
        ,
        CertiflexicateFieldTypes::CertiflexicateByteContent =>
          Some(SIGNATURESFIELD_BYTECONTENT_001.to_string())
        ,
        CertiflexicateFieldTypes::CertiflexicateSignatureData =>
          Some(SIGNATURESFIELD_SIGNATUREDATA_001.to_string())
        ,
    };
    if let Some(s) = opt {
      if !signed_fields.contains(&s) {
        signed_fields.push(s);
      };
    };
  };
  signed_fields

}


impl CertiflexicateFieldTypes {

  fn get_cmp(
      &self,
      other: &CertiflexicateFieldTypes,
  ) -> std_cmp_Ordering {
    self.get_priority_for_field_type()
        .cmp(&other.get_priority_for_field_type())
  }

}


pub(
    in super::super
) fn sort_claimed_signed_fields(
    v: &mut [CertiflexicateFieldTypes],
) {
  v.sort_by(CertiflexicateFieldTypes::get_cmp)
}


impl CertiflexicateFieldTypes {

  //∵ keep numbers
  fn get_u32_for_field_type(&self) -> u32 {
    match self {
      CertiflexicateFieldTypes::CertiflexicateIdentifier => 1,
      CertiflexicateFieldTypes::CertiflexicateVersion => 2,
      CertiflexicateFieldTypes::CertiflexicatePublicKey => 3,
      CertiflexicateFieldTypes::CertiflexicateByteContent => 5,
      CertiflexicateFieldTypes::CertiflexicateSignatureData => 4,
    }
  }

  //∵ keep order
  fn get_priority_for_field_type(&self) -> u32 {
    match self {
      CertiflexicateFieldTypes::CertiflexicateIdentifier => 1,
      CertiflexicateFieldTypes::CertiflexicateVersion => 2,
      CertiflexicateFieldTypes::CertiflexicatePublicKey => 3,
      CertiflexicateFieldTypes::CertiflexicateByteContent => 10,
      CertiflexicateFieldTypes::CertiflexicateSignatureData => 99,
    }
  }

  fn get_signable_for_field(
      &self,
  ) -> Option<DataFields> {
    match self {
      CertiflexicateFieldTypes::CertiflexicateIdentifier => None,
      CertiflexicateFieldTypes::CertiflexicateVersion => None,
      CertiflexicateFieldTypes::CertiflexicatePublicKey => None,
      CertiflexicateFieldTypes::CertiflexicateByteContent => Some(
          DataFields::Bytes
      ),
      CertiflexicateFieldTypes::CertiflexicateSignatureData => None,
    }
  }

}


pub(
    in super::super
) fn get_byte_slices_for_fields(
    v: &Vec<CertiflexicateFieldTypes>,
) -> Vec<Vec<u8>> {
  let mut byte_slices = Vec::with_capacity(v.len());
  for item in v {
    byte_slices.push(item
        .get_u32_for_field_type()
        .to_le_bytes()
        .as_slice()
        .to_vec()
    );
  };
  byte_slices
  
}


impl CertiflexicateFieldTypes {

  fn get_field_for_signable_data(
      signable: &DataFields,
  ) -> CertiflexicateFieldTypes {
    match signable {
      DataFields::Bytes => CertiflexicateFieldTypes
          ::CertiflexicateByteContent
      ,
    }
  }

}


impl CertiflexicateFieldTypes {

  pub(
      in super::super
  ) fn get_fields_for_self_signed_public_key() -> Vec<
      CertiflexicateFieldTypes
  > {
    vec![
        CertiflexicateFieldTypes::CertiflexicateIdentifier,
        CertiflexicateFieldTypes::CertiflexicateVersion,
        CertiflexicateFieldTypes::CertiflexicatePublicKey,
        CertiflexicateFieldTypes::CertiflexicateSignatureData,
    ]
  }

  pub(
      in super::super
  ) fn get_necessary_fields_and_signables(
      signables: &[DataFields],
  ) -> Vec<
      CertiflexicateFieldTypes
  > {
    let mut v = CertiflexicateFieldTypes
        ::get_fields_for_self_signed_public_key()
    ;
    if !signables.is_empty() {
      let mut added: Vec<&DataFields> = Vec::with_capacity(signables.len());
      for item in signables {
        if !added.contains(&item) {
          let field = CertiflexicateFieldTypes
              ::get_field_for_signable_data(item)
          ;
          added.push(item);
          if !v.contains(&field) {
            v.push(field);
          };
        };
      };
    };
    v
  }

  pub(
      in super::super
  ) fn filter_additional_fields_if_necessary_fields_are_included(
      fields: &[CertiflexicateFieldTypes],
  ) -> Result<
      Vec<CertiflexicateFieldTypes>,
      ErrorCertiflexicate,
  > {
    let nec = CertiflexicateFieldTypes
        ::get_fields_for_self_signed_public_key()
    ;
    let mut sth_missing = false;
    for item in &nec {
      if !fields.contains(item) {
        sth_missing = true;
      };
    };
    if !sth_missing{
      let mut addi = Vec::with_capacity(fields.len());
      for item in fields {
        if !nec.contains(item)
            && !addi.contains(item)
        {
          addi.push(item.clone());
        };
      };
      Ok(addi)
    } else {
      Err(ErrorCertiflexicate::signable_err(
          "missing items for signing",
      ))
    }
  }

  pub(
      in super::super
  ) fn get_additional_signables(
      fields: &[CertiflexicateFieldTypes],
  ) -> Vec<
      DataFields
  > {
    let mut signables = Vec::with_capacity(fields.len());
    let nec = CertiflexicateFieldTypes
        ::get_fields_for_self_signed_public_key()
    ;
    for item in fields {
      if !nec.contains(item) {
        if let Some(s) = item.get_signable_for_field() {
          if !signables.contains(&s) {
            signables.push(s);
          };
        };
      };
    };
    signables
  }
  
}



#[cfg(test)]
mod tests {

  use super::{
    CertiflexicateFieldTypes,
    sort_claimed_signed_fields,
  };

  #[test]
  fn sort_order_001() {
    let v1 = vec![
        CertiflexicateFieldTypes::CertiflexicateIdentifier,
        CertiflexicateFieldTypes::CertiflexicateVersion,
        CertiflexicateFieldTypes::CertiflexicatePublicKey,
        CertiflexicateFieldTypes::CertiflexicateByteContent,
        CertiflexicateFieldTypes::CertiflexicateSignatureData,
    ];
    let mut v2 = vec![
        CertiflexicateFieldTypes::CertiflexicateSignatureData,
        CertiflexicateFieldTypes::CertiflexicatePublicKey,
        CertiflexicateFieldTypes::CertiflexicateVersion,
        CertiflexicateFieldTypes::CertiflexicateIdentifier,
        CertiflexicateFieldTypes::CertiflexicateByteContent,
    ];
    sort_claimed_signed_fields(&mut v2);
    assert!(v1 == v2)
  }

}

