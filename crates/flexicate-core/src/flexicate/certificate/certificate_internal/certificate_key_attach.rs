

// certificate_key_attach

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
  ErrorCertiflexicate,
};


impl Certiflexicate {

  pub(
      super
  ) fn attach_unencrypted_ed25519_1_secret_key_to_cert_for_self_signing(
      &mut self,
      secret_key_data: &[u8; 32],
  ) -> Result<
      (),
      ErrorCertiflexicate,
  > {
    let pk = self.get_public_key_info_mut_ref()?;
    pk.perhaps_add_secret_key_data(secret_key_data)
  }

}

