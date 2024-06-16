use openmls::credentials::CredentialWithKey;
use openmls::framing::{MlsMessageIn, MlsMessageInBody, ProcessedMessageContent, ProtocolMessage};
use openmls::group::config::CryptoConfig;
use openmls::group::StagedCommit;
use openmls::prelude::{
    Ciphersuite, KeyPackage, MlsGroup, MlsGroupConfig, TlsDeserializeTrait, TlsSerializeTrait,
};
use openmls::treesync::RatchetTreeIn;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::credential::make_credential;
use crate::key_service::KeyService;

pub struct BenchConfig {
    pub provider: OpenMlsRustCrypto,
    pub ciphersuite: Ciphersuite,
    pub group_config: MlsGroupConfig,
    pub self_credential: CredentialWithKey,
    pub self_signer: SignatureKeyPair,
}

impl Default for BenchConfig {
    fn default() -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
        let provider = OpenMlsRustCrypto::default();
        let group_config = MlsGroupConfig::builder()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .use_ratchet_tree_extension(false)
            .build();
        let (self_credential, self_signer) =
            make_credential(&ciphersuite, &provider, "Alice".into()).unwrap();
        BenchConfig {
            provider,
            ciphersuite,
            group_config,
            self_credential,
            self_signer,
        }
    }
}

pub fn create_group(bench_config: &BenchConfig) -> MlsGroup {
    MlsGroup::new(
        &bench_config.provider,
        &bench_config.self_signer,
        &bench_config.group_config,
        bench_config.self_credential.clone(),
    )
    .expect("Failed to create group")
}

pub fn create_group_with_members(bench_config: &BenchConfig, key_service: &KeyService) -> MlsGroup {
    let members = key_service.all_data();
    let mut local_group = create_group(bench_config);

    // Mend tree by updating each leaf
    for (i, member) in members.iter().enumerate() {
        let (message_out, welcome_out, group_info) = local_group
            .add_members(
                &bench_config.provider,
                &bench_config.self_signer,
                &[member.key_package.clone()],
            )
            .expect("Failed to add members");

        local_group
            .merge_pending_commit(&bench_config.provider)
            .expect("Failed to merge pending commits");

        let ratchet_tree_in: RatchetTreeIn = local_group.export_ratchet_tree().into();

        let welcome_in = MlsMessageIn::tls_deserialize(
            &mut welcome_out
                .tls_serialize_detached()
                .expect("Deserialize out")
                .as_slice(),
        )
        .expect("Deserialize in");

        if let MlsMessageInBody::Welcome(welcome) = welcome_in.extract() {
            let mut remote_group = MlsGroup::new_from_welcome(
                &bench_config.provider,
                &bench_config.group_config,
                welcome.clone(),
                Some(ratchet_tree_in.clone()),
            )
            .expect("Group from welcome");
            let (update_out, _, _) = remote_group
                .self_update(&bench_config.provider, &member.signature_pair)
                .expect("Failed to update remote leaf");
            //remote_group
            //    .merge_pending_commit(&bench_config.provider)
            //    .expect("Failed to merge pending commits");

            let update_in: MlsMessageInBody = MlsMessageIn::tls_deserialize_exact(
                update_out
                    .tls_serialize_detached()
                    .expect("Serialize update"),
            )
            .expect("Deserialize update")
            .extract();

            if let MlsMessageInBody::PrivateMessage(update_message) = update_in {
                let processed_update = local_group
                    .process_message(&bench_config.provider, update_message)
                    .expect("Process update");

                if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                    processed_update.into_content()
                {
                    local_group.merge_staged_commit(&bench_config.provider, *staged_commit);
                } else {
                    panic!("Not a commit");
                }
            } else {
                panic!("Not a PrivateMessage");
            }
        } else {
            panic!("Not a welcome message");
        }

        eprint!("\rMember {} done", i);
    }
    eprintln!();

    //local_group
    //    .commit_to_pending_proposals(&bench_config.provider, &bench_config.self_signer)
    //    .expect("Commit to update proposals");
    //
    //local_group
    //    .merge_pending_commit(&bench_config.provider)
    //    .expect("Failed to merge pending commits");

    //println!("Done with mending group");

    local_group
}
