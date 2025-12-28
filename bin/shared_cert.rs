// Shared certificate for testing - uses a fixed certificate
// In production, load certificates from files or the profile

use rustls::{Certificate, PrivateKey};

// Pre-generated self-signed certificate for testing
// Generated once with rcgen, then hardcoded so both client and server use the same cert
const TEST_CERT_DER: &[u8] = include_bytes!("test_cert.der");
const TEST_KEY_DER: &[u8] = include_bytes!("test_key.der");

pub struct TestCertificate {
    pub cert: Certificate,
    #[allow(dead_code)]
    pub key: PrivateKey,
}

pub fn get_test_certificate() -> TestCertificate {
    TestCertificate {
        cert: Certificate(TEST_CERT_DER.to_vec()),
        key: PrivateKey(TEST_KEY_DER.to_vec()),
    }
}
