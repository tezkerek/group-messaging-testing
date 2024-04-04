#![feature(test)]

extern crate test;

use anyhow::{bail, Result};
use credential::make_credential;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

mod credential;
mod key_service;

static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

fn join_from_welcome(
    provider: &OpenMlsRustCrypto,
    welcome_out: &MlsMessageOut,
    group_config: &MlsGroupConfig,
    ratchet_tree_in: RatchetTreeIn,
) -> Result<MlsGroup> {
    let ser_welcome = welcome_out.tls_serialize_detached()?;
    let welcome_in = MlsMessageIn::tls_deserialize(&mut ser_welcome.as_slice())?;

    if let MlsMessageInBody::Welcome(welcome) = welcome_in.extract() {
        let group =
            MlsGroup::new_from_welcome(provider, group_config, welcome, Some(ratchet_tree_in))?;
        Ok(group)
    } else {
        bail!("Not a welcome message");
    }
}

fn main() -> Result<()> {
    Ok(())
}
