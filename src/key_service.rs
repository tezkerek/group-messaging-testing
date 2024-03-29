use std::collections::HashMap;

use anyhow::Result;
use openmls::prelude::*;

use crate::credential::{create_keypackage, make_credential};

pub struct KeyService {
    packages: HashMap<Vec<u8>, KeyPackage>,
}

impl KeyService {
    pub fn new() -> Self {
        KeyService {
            packages: Default::default(),
        }
    }

    pub fn get_by_credential(&self, credential: &Credential) -> Option<&KeyPackage> {
        self.packages.get(credential.identity())
    }

    pub fn publish(&mut self, identity: Vec<u8>, key_package: KeyPackage) {
        self.packages.insert(identity, key_package);
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
            let key_package =
                create_keypackage(ciphersuite.clone(), provider, new_credential, &new_signer)?;
            self.publish(identity.into(), key_package);
        }

        Ok(())
    }

    // pub fn iter(&self) { self.packages.iter() }
    pub fn packages(&self) -> &HashMap<Vec<u8>, KeyPackage> { &self.packages }
}
