

// signatures_data_collector

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
  SignatureData,
  super::{
    signature_fields::{
      CertiflexicateFieldTypes,
      field_types::{
        get_byte_slices_for_fields,
      },
    },
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
  },
};


const VALUESEPERATOR: u8 = u8::MIN;

const FIELDVALUESEPERATOR: [u8; 2] = [u8::MIN, u8::MIN];



fn add_owning_vecs_to_vec_with_seperator(
    main: &mut Vec<u8>,
    mut v: Vec<Vec<u8>>,
) {
  let mut i = 0;
  let v_len = v.len();
  for mut item in v.drain(..) {
    main.append(&mut item);
    i += 1;
    if i < v_len {
      main.push(VALUESEPERATOR);
    };
  };
}


fn add_borrowed_vecs_to_vec_with_seperator(
    main: &mut Vec<u8>,
    v: &Vec<Vec<u8>>,
) {
  let mut i = 0;
  let v_len = v.len();
  for item in v {
    for jtem in item {
      main.push(*jtem);
    };
    i += 1;
    if i < v_len {
      main.push(VALUESEPERATOR);
    };
  };
}


impl SignatureData {

  fn get_data_for_signature(
      &self,
      data: &mut Vec<u8>,
      fields_u8: &Vec<Vec<u8>>,
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let pk = self.get_sig_public_key_info_ref()?;
    let pk_data = pk.get_public_key_data_to_sign()?;
    data.extend_from_slice(self.version.to_le_bytes().as_slice());
    data.push(VALUESEPERATOR);
    data.extend_from_slice(
        &(self.identifier.len() as u64).to_le_bytes()
    );
    data.extend_from_slice(self.identifier.as_bytes());
    data.push(VALUESEPERATOR);
    data.extend_from_slice(
        &(self.comment.len() as u64).to_le_bytes()
    );
    data.extend_from_slice(self.comment.as_bytes());
    data.push(VALUESEPERATOR);
    data.extend_from_slice(
        &(self.start_date.len() as u64).to_le_bytes()
    );
    data.extend_from_slice(self.start_date.as_bytes());
    data.push(VALUESEPERATOR);
    data.extend_from_slice(
        &(self.stop_date.len() as u64).to_le_bytes()
    );
    data.extend_from_slice(self.stop_date.as_bytes());
    data.push(VALUESEPERATOR);
    add_borrowed_vecs_to_vec_with_seperator(data, fields_u8);
    data.push(VALUESEPERATOR);
    add_owning_vecs_to_vec_with_seperator(data, pk_data);
    data.push(VALUESEPERATOR);
    data.extend_from_slice(
        &(self.nonce.len() as u64).to_le_bytes()
    );
    data.extend_from_slice(self.nonce.as_bytes());
    data.push(VALUESEPERATOR);
    Ok(())
  }

}


impl SignatureData {

  pub(super) fn get_data_for_signed_fields(
      &self,
      cert: &Certiflexicate,
  ) -> Result<
      Vec<u8>,
      ErrorCertiflexicate,
  > {
    let mut data = Vec::new();
    let fields_u8 = get_byte_slices_for_fields(
        &self.claimed_signed_fields,
    );
    let mut a_error = Ok(());
    if fields_u8.len() == self.claimed_signed_fields.len() {
      let mut added = Vec::with_capacity(self.claimed_signed_fields.len());
      for (ct, item) in self
          .claimed_signed_fields
          .iter()
          .enumerate()
      {
        if !added.contains(&item) {
          data.extend_from_slice(&fields_u8[ct]);
          match item {
            CertiflexicateFieldTypes::CertiflexicateIdentifier => {
              data.extend_from_slice(
                  &(cert.certiflexicate.len() as u64).to_le_bytes()
              );
              data.extend_from_slice(cert.certiflexicate.as_bytes());
              data.push(VALUESEPERATOR);
            },
            CertiflexicateFieldTypes::CertiflexicateVersion => {
              data.extend_from_slice(cert.version.to_le_bytes().as_slice());
              data.push(VALUESEPERATOR);
            },
            CertiflexicateFieldTypes::CertiflexicatePublicKey => {
              let pk = cert.get_public_key_info_ref()?;
              let pk_data = pk.get_public_key_data_to_sign()?;
              add_owning_vecs_to_vec_with_seperator(&mut data, pk_data);
              data.push(VALUESEPERATOR);
            },
            CertiflexicateFieldTypes::CertiflexicateByteContent => {
              if let Some(bc) = &cert.byte_content {
                data.extend_from_slice(&(bc.len() as u64).to_le_bytes());
                data.extend_from_slice(bc);
                data.push(VALUESEPERATOR);
              } else {
                a_error = Err(ErrorCertiflexicate::signable_err(
                    "no byte content",
                ))
              };
            },
            CertiflexicateFieldTypes::CertiflexicateSignatureData => {
              self.get_data_for_signature(
                  &mut data,
                  &fields_u8,
              )?;
            },
          };
          data.extend_from_slice(FIELDVALUESEPERATOR.as_slice());
          added.push(item);
        };
        if a_error.is_err() {
          break;
        };
      };
    } else {
      a_error = Err(ErrorCertiflexicate::signable_err(
          "fields length",
      ))
    };
    if let Err(e) = a_error {
      Err(e)
    } else {
      Ok(data)
    }
  }

}

