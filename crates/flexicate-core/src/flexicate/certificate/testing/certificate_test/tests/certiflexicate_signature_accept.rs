

// certiflexicate_signature_accept

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



#[cfg(test)]
mod tests {

  use toml as tomler;

  use super::{
    super::{
      Certiflexicate,
      CERTIFICATE_STRING_VALID_001,
      //DataContent,
      SECRET_TEST_KEY_BYTES,
      SignatureAccepted,
    },
  };


  #[test]
  fn certificate_self_signed_accept_signature_suc_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "",
            1,
        )
    );
    if let Ok(mut cert) = res {
      let sigs = cert.get_verified_but_unchecked_signatures(&[]).unwrap();
      assert!(sigs.len() == 1);
      if let SignatureAccepted::NotAccepted(sig) = &sigs[0] {
        assert!(cert.accept_signature(&sig).is_err());
        let attached = cert
            .attach_secret_key(
                &SECRET_TEST_KEY_BYTES,
            )
        ;
        assert!(attached.is_ok());
        assert!(cert.accept_signature(&sig).is_ok());
        assert!(cert.accept_signature(&sig).is_err());
        let sigs2 = cert.get_verified_but_unchecked_signatures(&[]).unwrap();
        assert!(sigs2.len() == 1);
        if let SignatureAccepted::AcceptedSelf(sig2) = &sigs2[0] {
          assert!(cert.accept_signature(&sig2).is_err());
        } else {
          panic!();
        };
      } else {
        panic!();
      };
    } else {
      panic!();
    };
    
  }

  #[test]
  fn certificate_self_signed_accept_signature_fail_001() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001
    );
    if let Ok(mut cert) = res {
      let sigs = cert.get_verified_but_unchecked_signatures(&[]).unwrap();
      assert!(sigs.len() == 1);
      if let SignatureAccepted::AcceptedSelf(sig) = &sigs[0] {
        assert!(cert.accept_signature(&sig).is_err());
      } else {
        panic!();
      };
    } else {
      panic!();
    };
    
  }

  #[test]
  fn certificate_self_signed_accept_signature_fail_002() {
    let res = tomler::from_str::<Certiflexicate>(
        &CERTIFICATE_STRING_VALID_001.replacen(
            "accepted_base64 = \"PCxp-jUDIIQ7MQ1x8LMMsTLCeAZYJnr9vr9tlTMHRLx2MjYynw4K6fsmY53DA87BB290EAXpmzF-TdtjNLWhAQ==\"",
            "",
            1,
        )
    );
    if let Ok(mut cert) = res {
      let sigs = cert.get_verified_but_unchecked_signatures(&[]).unwrap();
      assert!(sigs.len() == 1);
      if let SignatureAccepted::NotAccepted(sig) = &sigs[0] {
        assert!(cert.accept_signature(&sig).is_err());
      } else {
        panic!();
      };
    } else {
      panic!();
    };
    
  }

}

