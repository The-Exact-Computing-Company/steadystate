// backend/src/compute/mod.rs

use crate::models::{Session, SessionRequest};

pub mod local_provider;

#[cfg(test)]
mod tests;

#[async_trait::async_trait]
pub trait ComputeProvider: Send + Sync + std::fmt::Debug {
    fn id(&self) -> &'static str;

    async fn start_session(
        &self,
        session_id: &str,
        request: &SessionRequest,
    ) -> anyhow::Result<crate::models::SessionStartResult>;

    async fn terminate_session(
        &self,
        session: &Session,
    ) -> anyhow::Result<()>;
}
