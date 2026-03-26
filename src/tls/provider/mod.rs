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

//! Crypto provider configuration for TLS connections.
//!
//! This module provides the `provider()` function which creates a rustls CryptoProvider
//! configured based on the optional TlsProfile and environment variables.
//!
//! Ztunnel uses `rustls` with pluggable crypto modules. All crypto MUST be done via
//! the providers in this module.
//!
//! One exception is CSR generation which doesn't currently have a plugin mechanism
//! (https://github.com/rustls/rcgen/issues/228). In that case, and any future ones,
//! it is critical to guard the code with appropriate `cfg` guards.
//!
//! ## Logging
//!
//! Enable debug logging (`RUST_LOG=ztunnel::tls::provider=debug`) to see:
//! - Startup TLS configuration (cipher suites, kx groups, TLS versions)
//! - Per-connection TLS provider creation with effective settings
//! - Cipher suite/kx group filtering decisions

use std::sync::Once;

use crate::TLS12_ENABLED;

use crate::tls::profile::{TlsProfile, TlsVersion};

static LOG_ONCE: Once = Once::new();

/// Log TLS configuration once on first provider creation.
fn log_provider_init() {
    LOG_ONCE.call_once(|| {
        tracing::info!(
            crypto_provider = CRYPTO_PROVIDER,
            tls12_enabled = *TLS12_ENABLED,
            "TLS provider initialized"
        );
    });
}

// Backend-specific modules
#[cfg(feature = "tls-boring")]
mod boring;
#[cfg(feature = "tls-ring")]
mod ring;
#[cfg(feature = "tls-aws-lc")]
mod aws_lc;
#[cfg(feature = "tls-openssl")]
mod openssl;

// Re-export provider from the appropriate backend
#[cfg(feature = "tls-boring")]
pub use boring::provider;
#[cfg(feature = "tls-ring")]
pub use ring::provider;
#[cfg(feature = "tls-aws-lc")]
pub use aws_lc::provider;
#[cfg(feature = "tls-openssl")]
pub use openssl::provider;

// CRYPTO_PROVIDER constants - identifies which crypto backend is in use
#[cfg(feature = "tls-aws-lc")]
pub static CRYPTO_PROVIDER: &str = "tls-aws-lc";
#[cfg(feature = "tls-ring")]
pub static CRYPTO_PROVIDER: &str = "tls-ring";
#[cfg(feature = "tls-boring")]
pub static CRYPTO_PROVIDER: &str = "tls-boring";
#[cfg(feature = "tls-openssl")]
pub static CRYPTO_PROVIDER: &str = "tls-openssl";

// TLS version constants
static TLS_VERSIONS_13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static TLS_VERSIONS_12_AND_13: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// Get TLS versions based on optional profile configuration.
/// If profile is None, falls back to global TLS12_ENABLED flag.
pub fn tls_versions(
    profile: Option<&TlsProfile>,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match profile {
        Some(p) => {
            // If min is TLS 1.2, support both 1.2 and 1.3
            // If min is TLS 1.3, support only 1.3
            match p.min_protocol_version {
                TlsVersion::Tls12 => TLS_VERSIONS_12_AND_13,
                TlsVersion::Tls13 => TLS_VERSIONS_13_ONLY,
            }
        }
        None => {
            // No profile - use global flag
            if *TLS12_ENABLED {
                TLS_VERSIONS_12_AND_13
            } else {
                TLS_VERSIONS_13_ONLY
            }
        }
    }
}

/// Helper function to determine if TLS 1.2 should be enabled.
/// Uses profile if provided, otherwise falls back to TLS12_ENABLED env var.
pub(crate) fn is_tls12_enabled(profile: Option<&TlsProfile>) -> bool {
    profile.map_or(*TLS12_ENABLED, |p| p.is_tls12_enabled())
}

/// Build default cipher suites based on TLS version configuration.
/// Takes TLS 1.3 ciphers and TLS 1.2 ciphers (both ECDSA and RSA variants).
pub(crate) fn default_cipher_suites<T>(
    profile: Option<&TlsProfile>,
    tls13_256: T,
    tls13_128: T,
    tls12_ecdsa_256: T,
    tls12_ecdsa_128: T,
    tls12_rsa_256: T,
    tls12_rsa_128: T,
) -> Vec<T> {
    let mut suites = vec![tls13_256, tls13_128];
    if is_tls12_enabled(profile) {
        suites.extend([tls12_ecdsa_256, tls12_ecdsa_128, tls12_rsa_256, tls12_rsa_128]);
    }
    suites
}

/// Filter and map cipher suites from profile configuration.
///
/// This is a common helper used by all crypto provider implementations to:
/// 1. Map string cipher suite names to provider-specific types
/// 2. Log warnings for unknown/unsupported cipher suites
/// 3. Fall back to defaults if all specified suites are invalid (SEC-002 mitigation)
///
/// Returns None if profile has no custom cipher suites (use defaults).
/// Returns Some(filtered_suites) if profile specifies cipher suites and at least one is valid.
/// Returns None if all specified suites are invalid (fall back to defaults).
pub(crate) fn filter_cipher_suites<T, F>(
    profile: Option<&TlsProfile>,
    provider_name: &str,
    mapper: F,
) -> Option<Vec<T>>
where
    F: Fn(&str) -> Option<T>,
{
    let p = profile?;
    if p.cipher_suites.is_empty() {
        return None;
    }

    let custom_suites: Vec<T> = p
        .cipher_suites
        .iter()
        .filter_map(|name| {
            mapper(name).or_else(|| {
                tracing::warn!(
                    "Unknown cipher suite '{}' for {} provider, ignoring",
                    name,
                    provider_name
                );
                None
            })
        })
        .collect();

    if custom_suites.is_empty() {
        // All specified suites were invalid - fall back to defaults (SEC-002)
        tracing::warn!(
            provider = provider_name,
            "all requested cipher suites invalid, using defaults"
        );
        None
    } else {
        Some(custom_suites)
    }
}

/// Filter and map key exchange groups from profile configuration.
///
/// Similar to filter_cipher_suites but for key exchange groups (ECDH curves).
/// Falls back to defaults if all specified groups are invalid (SEC-002 mitigation).
pub(crate) fn filter_kx_groups<'a, F>(
    profile: Option<&TlsProfile>,
    provider_name: &str,
    mapper: F,
) -> Option<Vec<&'a dyn rustls::crypto::SupportedKxGroup>>
where
    F: Fn(&str) -> Option<&'a dyn rustls::crypto::SupportedKxGroup>,
{
    let p = profile?;
    if p.ecdh_curves.is_empty() {
        return None;
    }

    let custom_groups: Vec<_> = p
        .ecdh_curves
        .iter()
        .filter_map(|name| {
            mapper(name).or_else(|| {
                tracing::warn!(
                    "Unknown key exchange group '{}' for {} provider, ignoring",
                    name,
                    provider_name
                );
                None
            })
        })
        .collect();

    if custom_groups.is_empty() {
        // All specified groups were invalid - fall back to defaults (SEC-002)
        tracing::warn!(
            provider = provider_name,
            "all requested kx groups invalid, using defaults"
        );
        None
    } else {
        Some(custom_groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_versions_with_profile() {
        let profile_tls13_only = TlsProfile {
            min_protocol_version: TlsVersion::Tls13,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        let versions = tls_versions(Some(&profile_tls13_only));
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, rustls::ProtocolVersion::TLSv1_3);

        let profile_both = TlsProfile {
            min_protocol_version: TlsVersion::Tls12,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        };
        let versions = tls_versions(Some(&profile_both));
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn test_tls_versions_no_profile() {
        let versions = tls_versions(None);
        let expected_len = if *crate::TLS12_ENABLED { 2 } else { 1 };
        assert_eq!(
            versions.len(),
            expected_len,
            "None profile should fall back to TLS12_ENABLED env var"
        );
    }
}
