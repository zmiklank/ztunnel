// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Ring crypto provider implementation.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use crate::tls::profile::TlsProfile;

use super::{default_cipher_suites, filter_cipher_suites};

/// Map cipher suite name to ring's cipher suite type.
fn map_cipher_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;
    match name {
        // TLS 1.3 cipher suites
        "TLS_AES_256_GCM_SHA384" | "TLS13_AES_256_GCM_SHA384" => {
            Some(cipher_suite::TLS13_AES_256_GCM_SHA384)
        }
        "TLS_AES_128_GCM_SHA256" | "TLS13_AES_128_GCM_SHA256" => {
            Some(cipher_suite::TLS13_AES_128_GCM_SHA256)
        }
        // TLS 1.2 cipher suites (FIPS-compatible)
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            Some(cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
            Some(cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        }
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
            Some(cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
            Some(cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        }
        _ => None,
    }
}

/// Create a ring-based crypto provider.
pub fn provider(profile: Option<&TlsProfile>) -> Arc<CryptoProvider> {
    super::log_provider_init();
    use rustls::crypto::ring::cipher_suite as cs;

    let cipher_suites = if let Some(c) = filter_cipher_suites(profile, "ring", map_cipher_suite) {
        c
    } else {
        default_cipher_suites(
            profile,
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        )
    };

    tracing::debug!(
        has_profile = profile.is_some(),
        cipher_count = cipher_suites.len(),
        "tls provider created (ring does not support custom kx groups)"
    );

    // Note: ring does not support custom key exchange groups
    Arc::new(CryptoProvider { cipher_suites, ..rustls::crypto::ring::default_provider() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::profile::TlsVersion;

    #[test]
    fn test_provider_no_profile_uses_env_vars() {
        let provider = provider(None);
        // 2 TLS 1.3 ciphers + 4 TLS 1.2 ciphers (ECDSA + RSA) = 6 total
        let expected_cipher_count = if *crate::TLS12_ENABLED { 6 } else { 2 };
        assert_eq!(
            provider.cipher_suites.len(),
            expected_cipher_count,
            "None profile should respect TLS12_ENABLED env var"
        );
    }

    #[test]
    fn test_provider_all_invalid_cipher_suites_fallback() {
        let profile_all_invalid = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![
                "INVALID_CIPHER_1".to_string(),
                "NONEXISTENT_SUITE".to_string(),
                "FAKE_TLS_CIPHER".to_string(),
            ],
            ecdh_curves: vec![],
        };
        let provider = provider(Some(&profile_all_invalid));
        assert_eq!(
            provider.cipher_suites.len(),
            2,
            "All-invalid cipher suites should fall back to TLS 1.3 defaults (2 ciphers)"
        );
    }

    #[test]
    fn test_provider_mixed_valid_invalid_cipher_suites() {
        let profile_mixed = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![
                "INVALID_CIPHER".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "ANOTHER_INVALID".to_string(),
            ],
            ecdh_curves: vec![],
        };
        let provider = provider(Some(&profile_mixed));
        assert_eq!(
            provider.cipher_suites.len(),
            1,
            "Mixed valid/invalid should keep only valid cipher suites"
        );
    }
}
