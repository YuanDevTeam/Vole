use super::*;
use std::sync::Arc;

fn config_list(suite: HpkeSuite, key: &[u8]) -> Vec<u8> {
    config_list_with_name(suite, key, b"public.invalid")
}

fn config_list_with_name(suite: HpkeSuite, key: &[u8], name: &[u8]) -> Vec<u8> {
    let mut content = vec![7];
    content.extend_from_slice(&u16::from(suite.kem).to_be_bytes());
    content.extend_from_slice(&(key.len() as u16).to_be_bytes());
    content.extend_from_slice(key);
    content.extend_from_slice(&4u16.to_be_bytes());
    content.extend_from_slice(&u16::from(suite.sym.kdf_id).to_be_bytes());
    content.extend_from_slice(&u16::from(suite.sym.aead_id).to_be_bytes());
    content.extend_from_slice(&[0, name.len() as u8]);
    content.extend_from_slice(name);
    content.extend_from_slice(&[0, 0]);
    let mut list = ((content.len() + 4) as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(content.len() as u16).to_be_bytes());
    list.extend_from_slice(&content);
    list
}

fn vector_end(data: &[u8], at: usize, width: usize) -> usize {
    let length = match width {
        1 => usize::from(data[at]),
        2 => usize::from(u16::from_be_bytes([data[at], data[at + 1]])),
        _ => unreachable!(),
    };
    at + width + length
}

// Decode only the bounded ClientHello fixture. ECH AAD is ClientHelloOuter
// without the handshake header, with its encrypted payload replaced by zeroes.
fn encrypted_inner(wire: &[u8], hpke: &dyn Hpke, sk: &HpkePrivateKey, list: &[u8]) -> Vec<u8> {
    assert_eq!(&wire[..3], &[22, 3, 1]);
    assert_eq!(wire[5], 1);
    let mut hello = wire[9..].to_vec();
    let mut cursor = vector_end(&hello, 34, 1);
    cursor = vector_end(&hello, cursor, 2);
    cursor = vector_end(&hello, cursor, 1);
    let end = vector_end(&hello, cursor, 2);
    cursor += 2;
    while cursor < end {
        let kind = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
        let next = vector_end(&hello, cursor + 2, 2);
        if kind == 0xfe0d {
            let start = cursor + 4;
            assert_eq!(hello[start], 0); // outer
            assert_eq!(hello[start + 5], 7);
            let enc_start = start + 8;
            let payload_at = vector_end(&hello, start + 6, 2);
            let payload_start = payload_at + 2;
            let payload_end = vector_end(&hello, payload_at, 2);
            let enc = EncapsulatedSecret(hello[enc_start..payload_at].to_vec());
            let payload = hello[payload_start..payload_end].to_vec();
            hello[payload_start..payload_end].fill(0);
            let mut info = b"tls ech\0".to_vec();
            info.extend_from_slice(&list[2..]);
            return hpke.open(&enc, &info, &hello, &payload, sk).unwrap();
        }
        cursor = next;
    }
    panic!("missing real ECH extension");
}

#[test]
fn ech_receiver_algorithms_encrypt_real_rustls_client_hello() {
    // One real consumer for every KEM, then the remaining KDF/AEAD families.
    // This is a bounded crypto fixture, not a protocol/platform matrix.
    let indices = [0, 15, 30, 45, 60, 75, 90, 105, 120, 3, 6, 9, 12, 1, 2];
    for index in indices {
        let hpke = SUITES[index];
        let (pk, sk) = hpke.generate_key_pair().unwrap();
        assert!(valid_public_key(u16::from(hpke.suite().kem), &pk.0));
        let list = if index == 0 {
            let ordinary = config_list_with_name(hpke.suite(), &pk.0, b"public.0x123");
            assert!(
                crate::config::StaticEchConfig::from_config_list_for_backend(&ordinary, true)
                    .is_err()
            );
            let single_label = config_list_with_name(hpke.suite(), &pk.0, b"public");
            assert!(
                crate::config::StaticEchConfig::from_config_list_for_backend(&single_label, false)
                    .is_err()
            );
            ordinary
        } else {
            config_list(hpke.suite(), &pk.0)
        };
        let admitted =
            crate::config::StaticEchConfig::from_config_list_for_backend(&list, false).unwrap();
        let ech = rustls::client::EchConfig::new(admitted.as_bytes().into(), SUITES).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_ech(ech.into())
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut connection =
            rustls::ClientConnection::new(Arc::new(config), "inner.invalid".try_into().unwrap())
                .unwrap();
        let mut wire = Vec::new();
        connection.write_tls(&mut wire).unwrap();
        assert!(!wire.windows(13).any(|v| v == b"inner.invalid"));
        let plaintext = encrypted_inner(&wire, hpke, &sk, &list);
        assert!(plaintext.windows(13).any(|v| v == b"inner.invalid"));
        // Ciphertext is authenticated: the same receiver rejects different AAD.
        let (enc, ciphertext) = hpke.seal(b"fixture", b"aad", b"payload", &pk).unwrap();
        assert!(
            hpke.open(&enc, b"fixture", b"other", &ciphertext, &sk)
                .is_err()
        );
    }
}

#[test]
fn inherited_ech_reselects_the_final_backend_before_any_handshake() {
    let ordinary = SUITES[15];
    let (pk, _) = ordinary.generate_key_pair().unwrap();
    let first = config_list(ordinary.suite(), &pk.0);
    let named = SUITES[0];
    let (pk, _) = named.generate_key_pair().unwrap();
    let second = config_list(named.suite(), &pk.0);
    let mut list = ((first.len() + second.len() - 4) as u16)
        .to_be_bytes()
        .to_vec();
    list.extend_from_slice(&first[2..]);
    list.extend_from_slice(&second[2..]);
    let ordinary =
        crate::config::StaticEchConfig::from_config_list_for_backend(&list, false).unwrap();
    assert_eq!(ordinary.as_bytes(), first);
    assert_eq!(ordinary.for_backend(true).unwrap().as_bytes(), second);
    let unsupported =
        crate::config::StaticEchConfig::from_config_list_for_backend(&first, false).unwrap();
    assert!(unsupported.for_backend(true).is_err());
}
