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

//! TLS Profile configuration for runtime TLS settings.
//!
//! This module provides the `TlsProfile` struct which allows runtime configuration
//! of TLS settings (protocol versions, cipher suites, key exchange groups) via xDS.

use crate::TLS12_ENABLED;

/// TLS version enumeration for runtime configuration.
/// Ordered from oldest to newest for comparison (Tls12 < Tls13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// Runtime TLS profile configuration.
/// Matches Istio's MeshConfig.meshMTLS (TLSConfig) structure.
///
/// When a TlsProfile is present, all fields are used. When absent, ztunnel
/// falls back to environment variables (TLS12_ENABLED, COMPLIANCE_POLICY).
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Minimum TLS protocol version (required)
    pub min_protocol_version: TlsVersion,
    /// Cipher suites (as string names, e.g., "TLS_AES_256_GCM_SHA384")
    /// Empty means use provider defaults
    pub cipher_suites: Vec<String>,
    /// Key exchange groups (e.g., "P-256", "P-384", "X25519", "X25519MLKEM768")
    /// Empty means use provider defaults
    /// Note: Field named ecdh_curves for compatibility with Istio's meshMTLS API
    pub ecdh_curves: Vec<String>,
}

impl Default for TlsProfile {
    fn default() -> Self {
        Self {
            min_protocol_version: if *TLS12_ENABLED {
                TlsVersion::Tls12
            } else {
                TlsVersion::Tls13
            },
            cipher_suites: Vec::new(), // Empty means use defaults
            ecdh_curves: Vec::new(),   // Empty means use defaults
        }
    }
}

impl TlsProfile {
    /// Validate the TLS profile configuration and log warnings for potential issues.
    pub fn validate(&self) {
        // Warn if TLS 1.2 is minimum (security concern)
        if self.min_protocol_version == TlsVersion::Tls12 {
            tracing::warn!(
                "TLS profile configured with TLS 1.2 minimum. TLS 1.3 is recommended for better security."
            );
        }

        // Warn if PQC is requested but not available
        if self.ecdh_curves.iter().any(|c| c.contains("MLKEM")) {
            #[cfg(not(any(feature = "tls-aws-lc", feature = "tls-openssl")))]
            {
                tracing::warn!("PQC curve requested but crypto provider does not support it. PQC requires aws-lc-rs or OpenSSL >= 3.5.0");
            }
        }
    }

    /// Check if TLS 1.2 should be enabled based on min_protocol_version.
    pub fn is_tls12_enabled(&self) -> bool {
        self.min_protocol_version == TlsVersion::Tls12
    }

    /// Check if this profile is compatible with the current build configuration.
    pub fn is_compatible(&self) -> bool {
        // Check if PQC curve is requested and available
        let has_pqc_curve = self.ecdh_curves.iter().any(|c| c.contains("MLKEM"));

        if has_pqc_curve {
            #[cfg(feature = "tls-aws-lc")]
            return true;

            #[cfg(feature = "tls-openssl")]
            {
                #[cfg(ossl350)]
                {
                    return openssl::version::number() >= 0x30500000;
                }
                #[cfg(not(ossl350))]
                {
                    return false;
                }
            }

            #[cfg(not(any(feature = "tls-aws-lc", feature = "tls-openssl")))]
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_profile_validation() {
        // Test valid profile - validate() logs warnings but doesn't panic
        let valid_profile = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        valid_profile.validate(); // Should not panic

        // Test TLS 1.2 profile (should warn but not panic)
        let tls12_profile = TlsProfile {
            min_protocol_version: TlsVersion::Tls12,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        tls12_profile.validate(); // Should not panic
    }

    #[test]
    fn test_tls_profile_is_tls12_enabled() {
        let profile_tls12 = TlsProfile {
            min_protocol_version: TlsVersion::Tls12,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        assert!(profile_tls12.is_tls12_enabled());

        let profile_tls13 = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        assert!(!profile_tls13.is_tls12_enabled());
    }

    #[test]
    fn test_tls_profile_default() {
        let profile = TlsProfile::default();

        let expected_min = if *crate::TLS12_ENABLED {
            TlsVersion::Tls12
        } else {
            TlsVersion::Tls13
        };
        assert_eq!(
            profile.min_protocol_version, expected_min,
            "Default profile should respect TLS12_ENABLED"
        );
    }
}
