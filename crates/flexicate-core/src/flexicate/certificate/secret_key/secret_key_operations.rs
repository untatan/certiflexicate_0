

// secret_key_operations

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



use ed25519_dalek::{
  SigningKey as ed25519_dalek_SigningKey,
  Signature as ed25519_dalek_Signature,
  Signer,
  VerifyingKey as ed25519_dalek_VerifyingKey,
};

use rand::{
  rngs::{
    OsRng,
  },
};

use crate::{
  flexicate::{
    helpers::{
      base64::{
        get_urlsafe_string,
      },
    },
  },
};

use super::{
  SecretKeyData,
  super::{
    super::{
      error::{
        ErrorCertiflexicate,
      },
    },
  },
};


fn get_new_ed25519_dalek_signing_key() -> ed25519_dalek_SigningKey {
  ed25519_dalek_SigningKey::generate(&mut OsRng)
}


#[cfg(test)]
fn get_new_ed25519_dalek_signing_test_key() -> ed25519_dalek_SigningKey {

  use ed25519_dalek::{
    SECRET_KEY_LENGTH as ed25519_dalek_SECRET_KEY_LENGTH,
  };

  // base64: "rHshwwBcvt5U5jajCPriaut3sbJC6RHJ2Kgdto4r5E4="
  let secret_test_key_bytes: [u8; ed25519_dalek_SECRET_KEY_LENGTH] = [
      172, 123, 33, 195, 0, 92, 190, 222, 84, 230, 54,
      163, 8, 250, 226, 106,235, 119, 177, 178, 66, 233,
      17, 201, 216, 168, 29, 182, 142, 43, 228, 78,
  ];

  // base64: "IjD-8sTjv-slO65Tl0lR9xtnLfYkSUWJh2lhCO9Nnxw="
  // public_kex = [
  //    34, 48, 254, 242, 196, 227, 191, 235, 37, 59, 174,
  //    83, 151, 73, 81, 247, 27, 103, 45, 246, 36, 73, 69,
  //    137, 135, 105, 97, 8, 239, 77, 159, 28,
  //    ];

  let signing_key: ed25519_dalek_SigningKey = ed25519_dalek_SigningKey
      ::from_bytes(
            &secret_test_key_bytes,
      )
  ;
  //println!("signing_key TEST : {:?}", signing_key);
  signing_key
}


#[cfg(not(test))]
fn get_new_ed25519_dalek_signing_key_cfg() -> ed25519_dalek_SigningKey {
  get_new_ed25519_dalek_signing_key()
}


#[cfg(test)]
fn get_new_ed25519_dalek_signing_key_cfg() -> ed25519_dalek_SigningKey {
  println!("WARNING: Using TEST  signing_key !");
  get_new_ed25519_dalek_signing_test_key()
}


impl SecretKeyData {

  fn get_new_from_signing_key(
      sk: ed25519_dalek_SigningKey,
  ) -> SecretKeyData {
    SecretKeyData {
      signing_key: sk,
    }
  }

  fn get_new_existing_secret_data(
      secret_key_data: &[u8; 32],
  ) -> ed25519_dalek_SigningKey {
    //∵ TODO check if secret_key_data valid
    ed25519_dalek_SigningKey::from_bytes(secret_key_data)
  }

  fn sign_data_to_bytes(
      &self,
      data: &[u8],
  ) -> Result<
      ed25519_dalek_Signature,
      ErrorCertiflexicate,
  > {
    self
        .signing_key
        .try_sign(data)
        .map_err(|e| ErrorCertiflexicate::ed25519_err(
            &e.to_string(),
        ))
  }

}


impl SecretKeyData {

  pub(
      in super::super
  ) fn new() -> SecretKeyData {
    SecretKeyData {
      signing_key: get_new_ed25519_dalek_signing_key_cfg(),
    }
  }

  pub(
      in super::super
  ) fn get_new_from_existing_secret_data(
      secret_key_data: &[u8; 32],
  ) -> SecretKeyData {
    SecretKeyData::get_new_from_signing_key(
        SecretKeyData::get_new_existing_secret_data(
            secret_key_data,
        ),
    )
  }

  pub(
      in super::super
  ) fn get_new_checked_from_secret_data(
      secret_key_data: &[u8; 32],
      vk: &ed25519_dalek_VerifyingKey,
  ) -> Result<
      SecretKeyData,
      ErrorCertiflexicate,
  > {
    let signing_key = SecretKeyData
        ::get_new_existing_secret_data(secret_key_data)
    ;
    if &signing_key.verifying_key() == vk {
      Ok(SecretKeyData::get_new_from_signing_key(signing_key))
    } else {
      Err(ErrorCertiflexicate::attach_skey(
          "secret and public key do not seem to match",
      ))
    }
  }

  pub(
      in super::super
  ) fn get_base64_encoded_public_key(
      &self,
  ) -> String {
    get_urlsafe_string(
        self.signing_key.verifying_key().as_bytes()
    )
  }

  pub(
      in super::super
  ) fn get_public_key(
      &self,
  ) -> ed25519_dalek_VerifyingKey {
    self.signing_key.verifying_key()
  }

  pub(
      in super::super
  ) fn export_secret_key_bytes_unencrypted(
      &self,
  ) -> [u8; 32] {
    *self.signing_key.as_bytes()
  }

  pub(
      in super::super
  ) fn sign_data_to_bytes_signature(
      &self,
      data: &[u8],
  ) -> Result<
      Vec<u8>,
      ErrorCertiflexicate,
  > {
    let signature = self.sign_data_to_bytes(data)?;
    Ok(signature.to_vec())
  }

  pub(
      in super::super
  ) fn sign_data_to_base64_encoded_signature(
      &self,
      data: &[u8],
  ) -> Result<
      String,
      ErrorCertiflexicate,
  > {
    let signature = self.sign_data_to_bytes(data)?;
    Ok(get_urlsafe_string(&signature.to_vec()))
  }

}



#[cfg(test)]
mod tests {

  use crate::{
    flexicate::{
      helpers::{
        base64::{
          get_base64_decoded,
        },
      },
    },
  };

  use super::{
    SecretKeyData,
  };


  #[test]
  fn accepted_sig_001() {
    if let Ok(sig) = get_base64_decoded(
        "olPQNpL5GGeD69qSaV6snUcSjBQv37PZW5OHfFwZgDpgYjjzb0cJivikzYNY0VofmDEI6IfGqkPZbOamIsWEAg==",
    ) {
      //println!("sig : {:?}", sig);
      let sk = SecretKeyData::new();
      if let Ok(asig) = sk.sign_data_to_base64_encoded_signature(&sig) {
        //println!("accepted : {:?}", asig);
        assert!(
          "PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ=="
          == asig)
      } else {
        panic!();
      }
    } else {
      panic!();
    }
  }

  #[test]
  fn print_key_001() {
    let _sk = SecretKeyData::new();
    //println!("SecretKeyData : {:?}", sk.to_string());
    //println!("SecretKeyData : {:?}", sk);
  }

}

