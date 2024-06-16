use std::collections::HashMap;

use anyhow::Result;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use crate::credential::{create_keypackage, make_credential};

pub struct MemberData {
    pub key_package: KeyPackage,
    pub credential: CredentialWithKey,
    pub signature_pair: SignatureKeyPair,
}

pub struct KeyService {
    members: HashMap<Vec<u8>, MemberData>,
}

impl KeyService {
    pub fn new() -> Self {
        KeyService {
            members: Default::default(),
        }
    }

    pub fn generate(
        &mut self,
        ciphersuite: &Ciphersuite,
        provider: &impl OpenMlsCryptoProvider,
        count: usize,
    ) -> Result<()> {
        for i in 1..=count {
            let identity = format!("Member {}", i);
            let (new_credential, new_signer) =
                make_credential(ciphersuite, provider, identity.clone())?;
            let key_package = create_keypackage(
                ciphersuite.clone(),
                provider,
                new_credential.clone(),
                &new_signer,
            )?;

            let data = MemberData {
                key_package,
                credential: new_credential,
                signature_pair: new_signer,
            };
            self.members.insert(identity.into(), data);
        }

        Ok(())
    }

    pub fn all_data(&self) -> Vec<&MemberData> { self.members.values().collect() }
}
