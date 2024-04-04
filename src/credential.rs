use anyhow::{anyhow, Result};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

pub fn make_credential(
    ciphersuite: &Ciphersuite,
    provider: &impl OpenMlsCryptoProvider,
    name: String,
) -> Result<(CredentialWithKey, SignatureKeyPair)> {
    let me = Credential::new(name.into(), CredentialType::Basic)?;

    let sign_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())?;
    sign_keys
        .store(provider.key_store())
        .map_err(|_| anyhow!("Credential generation failed"))?;

    let credential_with_key = CredentialWithKey {
        credential: me,
        signature_key: sign_keys.public().into(),
    };

    Ok((credential_with_key, sign_keys))
}

pub(crate) fn create_keypackage(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsCryptoProvider,
    credential_with_key: CredentialWithKey,
    signer: &SignatureKeyPair,
) -> Result<KeyPackage> {
    let key_package = KeyPackage::builder()
        .build(
            CryptoConfig::with_default_version(ciphersuite),
            provider,
            signer,
            credential_with_key,
        )
        .map_err(|_| anyhow!("Keypackage building failed"))?;

    Ok(key_package)
}
