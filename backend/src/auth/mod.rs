// backend/src/auth/mod.rs

pub mod provider;
pub mod github;
pub mod gitlab;
pub mod orchid;
pub mod fake;

use std::sync::Arc;
use crate::state::AppState;

/// Registers all the built-in authentication provider factories.
/// This is the *only* place that needs to be modified to add a new provider.
pub fn register_builtin_providers(state: &AppState) {
    state.register_provider_factory(Arc::new(github::GitHubFactory));
    state.register_provider_factory(Arc::new(fake::FakeFactory));
    state.register_provider_factory(Arc::new(gitlab::GitLabFactory));
    state.register_provider_factory(Arc::new(orchid::OrchidFactory));
}
