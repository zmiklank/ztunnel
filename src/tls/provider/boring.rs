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

//! BoringSSL crypto provider implementation.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use crate::tls::profile::TlsProfile;

/// Create a BoringSSL-based crypto provider.
///
/// BoringSSL provider with 'fips-only' feature has a fixed cipher suite set:
/// - TLS13_AES_256_GCM_SHA384
/// - TLS13_AES_128_GCM_SHA256
///
/// Runtime cipher suite and key exchange group configuration is NOT possible with this provider.
/// The profile is intentionally ignored. See RFE Known Limitations section.
pub fn provider(profile: Option<&TlsProfile>) -> Arc<CryptoProvider> {
    super::log_provider_init();
    let _ = profile;
    Arc::new(boring_rustls_provider::provider())
}
