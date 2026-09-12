// backend/src/auth/mod.rs

pub mod fake;
pub mod github;
pub mod gitlab;
pub mod oidc;
pub mod provider;

use crate::state::AppState;
use std::sync::Arc;

/// Registers all the built-in authentication provider factories.
/// This is the *only* place that needs to be modified to add a new provider.
pub fn register_builtin_providers(state: &AppState) {
    state.register_provider_factory(Arc::new(github::GitHubFactory));
    state.register_provider_factory(Arc::new(fake::FakeFactory));
    state.register_provider_factory(Arc::new(gitlab::GitLabFactory));
    state.register_provider_factory(Arc::new(oidc::OidcFactory));
}
