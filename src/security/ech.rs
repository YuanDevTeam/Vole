//! Adapter for official Rust HPKE through rustls's public provider seam. The
//! wire enum paths are publicly exported but internal to rustls: keep them here.
use hpke::{Deserializable, Serializable, aead::Aead};
use rand::SeedableRng;
use rustls::internal::msgs::{
    enums::{HpkeAead, HpkeKdf, HpkeKem},
    handshake::HpkeSymmetricCipherSuite,
};
use rustls::{
    Error,
    crypto::hpke::{
        EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
    },
};
use std::marker::PhantomData;

macro_rules! suites {
    ($($kem:ty),+ $(,)?) => {
        &[
        $(
            &Adapter::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha256, $kem>(PhantomData),
            &Adapter::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha384, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, $kem>(PhantomData),
            &Adapter::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha384, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha512, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, $kem>(PhantomData),
            &Adapter::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha512, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm128, hpke::kdf::KdfShake128, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm256, hpke::kdf::KdfShake128, $kem>(PhantomData),
            &Adapter::<hpke::aead::ChaCha20Poly1305, hpke::kdf::KdfShake128, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, $kem>(PhantomData),
            &Adapter::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, $kem>(PhantomData),
            &Adapter::<hpke::aead::ChaCha20Poly1305, hpke::kdf::KdfShake256, $kem>(PhantomData),
        )+
        ]
    };
}

pub(super) static SUITES: &[&dyn Hpke] = suites![
    hpke::kem::X25519HkdfSha256,
    hpke::kem::DhP256HkdfSha256,
    hpke::kem::DhP384HkdfSha384,
    hpke::kem::DhP521HkdfSha512,
    hpke::kem::MlKem768,
    hpke::kem::MlKem1024,
    hpke::kem::XWing,
    hpke::kem::MlKem768P256,
    hpke::kem::MlKem1024P384,
];

struct Adapter<A, D, K>(PhantomData<(A, D, K)>);
struct Sender<A: Aead, D: hpke::kdf::Kdf, K: hpke::Kem>(hpke::aead::AeadCtxS<A, D, K>);
struct Receiver<A: Aead, D: hpke::kdf::Kdf, K: hpke::Kem>(hpke::aead::AeadCtxR<A, D, K>);
impl<A, D, K> std::fmt::Debug for Adapter<A, D, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE adapter")
    }
}
impl<A: Aead, D: hpke::kdf::Kdf, K: hpke::Kem> std::fmt::Debug for Sender<A, D, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE sender")
    }
}
impl<A: Aead, D: hpke::kdf::Kdf, K: hpke::Kem> std::fmt::Debug for Receiver<A, D, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HPKE receiver")
    }
}
fn error(_: hpke::HpkeError) -> Error {
    Error::General("HPKE operation failed".into())
}
fn rng() -> Result<rand::rngs::StdRng, Error> {
    rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|_| Error::General("HPKE randomness unavailable".into()))
}
impl<
    A: Aead + Send + Sync + 'static,
    D: hpke::kdf::Kdf + Send + Sync + 'static,
    K: hpke::Kem + Send + Sync + 'static,
> HpkeSealer for Sender<A, D, K>
{
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(plaintext, aad).map_err(error)
    }
}
impl<
    A: Aead + Send + Sync + 'static,
    D: hpke::kdf::Kdf + Send + Sync + 'static,
    K: hpke::Kem + Send + Sync + 'static,
> HpkeOpener for Receiver<A, D, K>
{
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(ciphertext, aad).map_err(error)
    }
}
impl<
    A: Aead + Send + Sync + 'static,
    D: hpke::kdf::Kdf + Send + Sync + 'static,
    K: hpke::Kem + Send + Sync + 'static,
> Hpke for Adapter<A, D, K>
{
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::from(K::KEM_ID),
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::from(D::KDF_ID),
                aead_id: HpkeAead::from(A::AEAD_ID),
            },
        }
    }
    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (sk, pk) = K::gen_keypair_with_rng(&mut rng()?);
        Ok((
            HpkePublicKey(pk.to_bytes().to_vec()),
            sk.to_bytes().to_vec().into(),
        ))
    }
    fn setup_sealer(
        &self,
        info: &[u8],
        key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer>), Error> {
        let pk = <K as hpke::Kem>::PublicKey::from_bytes(&key.0).map_err(error)?;
        let (enc, ctx) =
            hpke::setup_sender_with_rng::<A, D, K>(&hpke::OpModeS::Base, &pk, info, &mut rng()?)
                .map_err(error)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(Sender(ctx)),
        ))
    }
    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener>, Error> {
        let sk = <K as hpke::Kem>::PrivateKey::from_bytes(key.secret_bytes()).map_err(error)?;
        let enc = <K as hpke::Kem>::EncappedKey::from_bytes(&enc.0).map_err(error)?;
        let ctx = hpke::setup_receiver::<A, D, K>(&hpke::OpModeR::Base, &sk, &enc, info)
            .map_err(error)?;
        Ok(Box::new(Receiver(ctx)))
    }
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut ctx) = self.setup_sealer(info, key)?;
        Ok((enc, ctx.seal(aad, plaintext)?))
    }
    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.setup_opener(enc, info, key)?.open(aad, ciphertext)
    }
}

pub(crate) fn valid_public_key(kem: u16, key: &[u8]) -> bool {
    fn valid<K: hpke::Kem>(key: &[u8]) -> bool {
        K::PublicKey::from_bytes(key).is_ok()
    }
    match kem {
        0x0020 => valid::<hpke::kem::X25519HkdfSha256>(key),
        0x0010 => valid::<hpke::kem::DhP256HkdfSha256>(key),
        0x0011 => valid::<hpke::kem::DhP384HkdfSha384>(key),
        0x0012 => valid::<hpke::kem::DhP521HkdfSha512>(key),
        0x0041 => valid::<hpke::kem::MlKem768>(key),
        0x0042 => valid::<hpke::kem::MlKem1024>(key),
        0x647a => valid::<hpke::kem::XWing>(key),
        0x0050 => valid::<hpke::kem::MlKem768P256>(key),
        0x0051 => valid::<hpke::kem::MlKem1024P384>(key),
        _ => false,
    }
}

#[cfg(test)]
#[path = "ech_tests.rs"]
mod tests;
