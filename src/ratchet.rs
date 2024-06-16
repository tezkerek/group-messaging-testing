use double_ratchet_2::{aead::encrypt, header::Header, ratchet::Ratchet};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RatchetGroup {
    local_ratchets: Vec<Ratchet<StaticSecret>>,
    remote_ratchets: Vec<Ratchet<StaticSecret>>,
}

impl RatchetGroup {
    pub fn new() -> Self {
        Self {
            local_ratchets: Vec::new(),
            remote_ratchets: Vec::new(),
        }
    }

    pub fn new_with_members(secrets: Vec<[u8; 32]>) -> Self {
        let ratchets_pairs: (Vec<_>, Vec<_>) = secrets.into_iter().map(Self::init_member).unzip();
        Self {
            local_ratchets: ratchets_pairs.0,
            remote_ratchets: ratchets_pairs.1,
        }
    }

    pub fn with_generated_members(count: usize) -> Self {
        let secrets: Vec<[u8; 32]> = (0..count)
            .map(|_| StaticSecret::random().to_bytes())
            .collect();
        Self::new_with_members(secrets)
    }

    pub fn encrypt_message(&mut self, msg: &[u8]) -> Vec<(Header<PublicKey>, Vec<u8>, [u8; 12])> {
        self.local_ratchets
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

    pub fn encrypt_from_member(
        &mut self,
        member_index: usize,
        msg: &[u8],
    ) -> (Header<PublicKey>, Vec<u8>, [u8; 12]) {
        self.remote_ratchets[member_index].ratchet_encrypt(msg, &[])
    }

    pub fn decrypt_message(
        &mut self,
        member_index: usize,
        header: &Header<PublicKey>,
        ciphertext: &[u8],
        nonce: &[u8; 12],
    ) -> Vec<u8> {
        self.local_ratchets[member_index].ratchet_decrypt(header, ciphertext, nonce, &[])
    }

    pub fn add_member(&mut self) {
        let secret = StaticSecret::random().to_bytes();
        let (mut remote_ratchet, pk) = Ratchet::<StaticSecret>::init_bob(secret);
        let mut local_ratchet = Ratchet::<StaticSecret>::init_alice(secret, pk);
        self.local_ratchets.push(local_ratchet);
        self.remote_ratchets.push(remote_ratchet);
    }

    pub fn remove_member(&mut self) {
        self.local_ratchets.pop();
        self.remote_ratchets.pop();
    }

    fn init_member(secret: [u8; 32]) -> (Ratchet<StaticSecret>, Ratchet<StaticSecret>) {
        let (mut remote_ratchet, pk) = Ratchet::<StaticSecret>::init_bob(secret);
        let mut local_ratchet = Ratchet::<StaticSecret>::init_alice(secret, pk);
        // Initialize remote ratchet as well
        let (header, ciphertext, nonce) = local_ratchet.ratchet_encrypt(b"init", &[]);
        remote_ratchet.ratchet_decrypt(&header, &ciphertext, &nonce, &[]);
        (local_ratchet, remote_ratchet)
    }
}

pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N], rand_chacha::rand_core::Error> {
    let mut output = [0u8; N];
    ChaCha20Rng::from_entropy().try_fill_bytes(&mut output)?;
    Ok(output)
}
