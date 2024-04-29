use double_ratchet_2::{aead::encrypt, header::Header, ratchet::Ratchet};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RatchetGroup {
    other_ratchets: Vec<Ratchet<StaticSecret>>,
}

impl RatchetGroup {
    pub fn new() -> Self {
        Self {
            other_ratchets: Vec::new(),
        }
    }

    pub fn new_with_members(secrets: Vec<[u8; 32]>) -> Self {
        Self {
            other_ratchets: secrets
                .into_iter()
                .map(|secret| Ratchet::<StaticSecret>::init_bob(secret).0)
                .collect(),
        }
    }

    pub fn with_generated_members(count: usize) -> Self {
        let secrets: Vec<[u8; 32]> = (0..count)
            .map(|_| StaticSecret::random().to_bytes())
            .collect();
        Self {
            other_ratchets: secrets
                .into_iter()
                .map(|secret| (secret.clone(), Ratchet::<StaticSecret>::init_bob(secret).1))
                .map(|(secret, bob_pk)| Ratchet::<StaticSecret>::init_alice(secret, bob_pk))
                .collect(),
        }
    }

    pub fn encrypt_message(&mut self, msg: &[u8]) -> Vec<(Header<PublicKey>, Vec<u8>, [u8; 12])> {
        self.other_ratchets
            .iter_mut()
            .map(|ratchet| ratchet.ratchet_encrypt(msg, &[]))
            .collect()
    }

    pub fn encrypt_message_efficiently(
        &mut self,
        msg: &[u8],
    ) -> (
        Vec<u8>,
        [u8; 12],
        Vec<(Header<PublicKey>, Vec<u8>, [u8; 12])>,
    ) {
        let secret = generate_random_bytes::<32>().expect("Failed to generate bytes");
        let (encrypted, nonce) = encrypt(&secret, msg, &[]);

        let member_ciphertexts = self.encrypt_message(&secret);

        (encrypted, nonce, member_ciphertexts)
    }
}

pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N], rand_chacha::rand_core::Error> {
    let mut output = [0u8; N];
    ChaCha20Rng::from_entropy().try_fill_bytes(&mut output)?;
    Ok(output)
}
