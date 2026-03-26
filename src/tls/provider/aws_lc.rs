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

//! AWS-LC-RS crypto provider implementation.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use crate::PQC_ENABLED;
use crate::tls::profile::TlsProfile;

use super::{default_cipher_suites, filter_cipher_suites, filter_kx_groups};

/// Map cipher suite name to aws-lc-rs's cipher suite type.
fn map_cipher_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    use rustls::crypto::aws_lc_rs::cipher_suite;
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

/// Map key exchange group name to aws-lc-rs's kx group type.
fn map_kx_group(name: &str) -> Option<&'static dyn rustls::crypto::SupportedKxGroup> {
    use rustls::crypto::aws_lc_rs::kx_group;
    match name {
        "X25519MLKEM768" => Some(kx_group::X25519MLKEM768),
        "X25519" => Some(kx_group::X25519),
        "P-256" | "SECP256R1" => Some(kx_group::SECP256R1),
        "P-384" | "SECP384R1" => Some(kx_group::SECP384R1),
        _ => None,
    }
}

/// Create an aws-lc-rs-based crypto provider.
pub fn provider(profile: Option<&TlsProfile>) -> Arc<CryptoProvider> {
    super::log_provider_init();
    use rustls::crypto::aws_lc_rs::{cipher_suite as cs, kx_group as kx};

    let cipher_suites = if let Some(c) = filter_cipher_suites(profile, "aws-lc-rs", map_cipher_suite) {
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

    let kx_groups = if let Some(g) = filter_kx_groups(profile, "aws-lc-rs", map_kx_group) {
        g
    } else if profile.is_none() && *PQC_ENABLED {
        vec![kx::X25519MLKEM768]
    } else {
        vec![kx::X25519, kx::SECP256R1, kx::SECP384R1]
    };

    tracing::debug!(
        has_profile = profile.is_some(),
        cipher_count = cipher_suites.len(),
        kx_count = kx_groups.len(),
        "tls provider created"
    );

    Arc::new(CryptoProvider { cipher_suites, kx_groups, ..rustls::crypto::aws_lc_rs::default_provider() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::profile::TlsVersion;

    #[test]
    fn test_provider_with_profile_pqc() {
        let profile_pqc = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec!["X25519MLKEM768".to_string()],
        };
        let provider = provider(Some(&profile_pqc));
        assert_eq!(
            provider.kx_groups.len(),
            1,
            "PQC profile should have X25519MLKEM768"
        );

        let profile_no_pqc = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        let provider = provider(Some(&profile_no_pqc));
        assert_eq!(
            provider.kx_groups.len(),
            3,
            "Empty ecdh_curves should use default kx groups (X25519, P-256, P-384)"
        );

        let profile_p256 = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec!["P-256".to_string()],
        };
        let provider = provider(Some(&profile_p256));
        assert_eq!(
            provider.kx_groups.len(),
            1,
            "Explicit P-256 should have 1 kx group"
        );
    }

    #[test]
    fn test_provider_with_profile_cipher_suites() {
        let profile_tls13_only = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        let provider = provider(Some(&profile_tls13_only));
        assert_eq!(
            provider.cipher_suites.len(),
            2,
            "TLS 1.3 only should have 2 cipher suites"
        );

        let profile_both = TlsProfile {
            min_protocol_version: TlsVersion::Tls12,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        let provider = provider(Some(&profile_both));
        assert_eq!(
            provider.cipher_suites.len(),
            4,
            "TLS 1.2 + 1.3 should have 4 cipher suites"
        );
    }

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
    fn test_provider_all_invalid_kx_groups_fallback() {
        let profile_all_invalid = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec![
                "INVALID_CURVE".to_string(),
                "NONEXISTENT_GROUP".to_string(),
                "FAKE_KX_GROUP".to_string(),
            ],
        };
        let provider = provider(Some(&profile_all_invalid));
        assert_eq!(
            provider.kx_groups.len(),
            3,
            "All-invalid kx groups should fall back to defaults (X25519, P-256, P-384)"
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
